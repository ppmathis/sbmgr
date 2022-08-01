#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

declare -gr SBMGR_CONFIG_FILE="/etc/sbmgr.conf"
declare -gA SBMGR_TARGET_MOUNTS=()

# Main entrypoint for script, called at the very bottom of this script
function main() {
	local -ra _args=("${@}")
	local -r _action="${1:-}"; shift || true

	# Setup cleanup trap to not leave a mess
	trap _sbmgr_cleanup EXIT

	# Initialize state for script execution
	_sbmgr_check_prereqs
	_sbmgr_config_load
	_sbmgr_prepare_tmpdir

	# Run requested action
	case "${_action}" in
		install)
			_sbmgr_reexec_mountns "${_args[@]}"
			_sbmgr_install_script
			_sbmgr_generate_secureboot_keys
			_sbmgr_mount_targets
			_sbmgr_install_bootloader
			_sbmgr_install_keytool
			_sbmgr_install_hooks
			_sbmgr_sync_secureboot_keys

			_log "========================================================================================================================"
			_log "Successfully installed sbmgr. Ensure to install at least one kernel or your system will no longer boot!"
			_log "========================================================================================================================"
		;;

		uninstall)
			_sbmgr_reexec_mountns "${_args[@]}"
			_sbmgr_mount_targets
			_sbmgr_uninstall_hooks

			# TODO: Decide on a sane strategy for uninstalls.
			# Unconditionally removing the bootloader can be dangerous and result in the system being unbootable.
			# As of right now, it seems like a better choice to leave a fully working bootloader and let the user cleanup.
			#
			# _sbmgr_uninstall_keytool
			# _sbmgr_uninstall_bootloader

			_sbmgr_remove_secureboot_keys
			_sbmgr_uninstall_script

			_log "========================================================================================================================"
			_log "Successfully uninstalled sbmgr. Configuration and state data stored at [%s] has been kept." "${SBMGR_DATA_PATH}"
			_log "========================================================================================================================"
		;;

		install-kernel | update-kernel)
			_sbmgr_ensure_install
			_sbmgr_reexec_mountns "${_args[@]}"
			_sbmgr_mount_targets
			_sbmgr_kernel_deploy "${1}"
		;;

		remove-kernel)
			_sbmgr_ensure_install
			_sbmgr_reexec_mountns "${_args[@]}"
			_sbmgr_mount_targets
			_sbmgr_kernel_remove "${1}"
		;;

		help | *)
			echo "usage: ${0} <ACTION> [ARGS...]" >&2
			echo "> install: Install sbmgr to your system including systemd-boot and KeyTool"
			echo "> install-kernel <VERSION>: Install or update a specific kernel version"
			echo "> remove-kernel <VERSION>: Remove a specific kernel version"

			_sbmgr_cleanup >/dev/null
			exit 1
		;;
	esac
}

# Checks if system meets requirements for running sbmgr
function _sbmgr_check_prereqs() {
	# Ensure required commands are present on system
	_ensure_commands \
		"bootctl" \
		"cert-to-efi-sig-list" \
		"objcopy" \
		"openssl" \
		"realpath" \
		"rsync" \
		"sbsign" \
		"sbverify" \
		"sign-efi-sig-list" \
		"uuidgen"
}

# Cleans up any leftovers the script might currently have and exits gracefully
function _sbmgr_cleanup() {
	local -r _exit_code="${?}"
	local _target_mp

	# Unmount temporary mountpoints and delete all folders
	for _target_mp in "${SBMGR_TARGET_MOUNTS[@]}"; do
		_log "Unmounting ${_target_mp}..."
		_cmd_run_silent umount "${_target_mp}"
		rmdir "${_target_mp}"
	done

	# Remove temporary directory
	if [[ -n "${SBMGR_TMP_DIR:-}" ]]; then
		_log "Cleaning up temporary directory [%s]..." "${SBMGR_TMP_DIR}"
		rm -rf "${SBMGR_TMP_DIR}"
	fi

	# Unassign trap handler to avoid multiple runs and exit gracefully
	_log "Gracefully exiting with code [%d]..." "${_exit_code}"
	trap - EXIT
	exit "${_exit_code}"
}

# Loads the sbmgr configuration
function _sbmgr_config_load() {
	# Define sane default values
	SBMGR_INSTALL_PATH="/usr/local/sbin/sbmgr"
	SBMGR_CMDLINE_PATH="/etc/kernel/cmdline"
	SBMGR_DATA_PATH="/var/lib/sbmgr"
	SBMGR_IMAGE_PREFIX="system"
	SBMGR_TARGETS=()

	SYSTEMD_BOOT_PRIMARY_EFI="EFI/systemd/systemd-bootx64.efi"
	SYSTEMD_BOOT_FALLBACK_EFI="EFI/BOOT/BOOTX64.EFI"
	EFISTUB_EFI_IMAGE="/usr/lib/systemd/boot/efi/linuxx64.efi.stub"
	KEYTOOL_EFI_IMAGE="/usr/lib/efitools/x86_64-linux-gnu/KeyTool.efi"
	OS_RELEASE_PATH="/etc/os-release"
	LINUX_KERNEL_PATH_PATTERN="/boot/vmlinuz-%s"
	LINUX_INITRD_PATH_PATTERN="/boot/initrd.img-%s"
	INITRD_POST_UPDATE_HOOK="/etc/initramfs/post-update.d/zz-sbmgr"
	KERNEL_INSTALL_HOOK="/etc/kernel/postinst.d/zz-sbmgr"
	KERNEL_REMOVE_HOOK="/etc/kernel/postrm.d/zz-sbmgr"

	# Load configuration file
	if [[ -r "${SBMGR_CONFIG_FILE}" ]]; then
		# shellcheck disable=SC1090
		source "${SBMGR_CONFIG_FILE}"
	else
		_log_fatal "Unable to read sbmgr configuration file [%s]" "${SBMGR_CONFIG_FILE}"
	fi

	# Expose variables globally as read-only
	declare -gr SBMGR_INSTALL_PATH
	declare -gr SBMGR_CMDLINE_PATH
	declare -gr SBMGR_DATA_PATH
	declare -gr SBMGR_IMAGE_PREFIX
	declare -gra SBMGR_TARGETS

	declare -gr SYSTEMD_BOOT_PRIMARY_EFI
	declare -gr SYSTEMD_BOOT_FALLBACK_EFI
	declare -gr EFISTUB_EFI_IMAGE
	declare -gr KEYTOOL_EFI_IMAGE
	declare -gr OS_RELEASE_PATH
	declare -gr LINUX_KERNEL_PATH_PATTERN
	declare -gr LINUX_INITRD_PATH_PATTERN
	declare -gr INITRD_POST_UPDATE_HOOK
	declare -gr KERNEL_INSTALL_HOOK
	declare -gr KERNEL_REMOVE_HOOK

	# Hardcore certain related config values
	declare -gr SBMGR_MOUNTS_PATH="${SBMGR_DATA_PATH}/mounts"
	declare -gr SBMGR_KEYS_PATH="${SBMGR_DATA_PATH}/keys"
}

# Determines cmdline to use for kernel deployments
# Warning: This function uses stdout to return the cmdline
function _sbmgr_determine_kernel_cmdline() {
	local _cmdline _root _root_device _root_fstype

	# If cmdline file exists, use this one as-is
	if [[ -f "${SBMGR_CMDLINE_PATH}" ]]; then
		# Read cmdline from file and ensure root= parameter was specified
		_cmdline="$(cat "${SBMGR_CMDLINE_PATH}")"
		if [[ ! "${_cmdline}" =~ root=[^\ ]+ ]]; then
			_log_fatal "Found cmdline file at [%s], but no root= parameter was specified. Aborting!" "${SBMGR_CMDLINE_PATH}"
		fi

		# Output cmdline as-is and return
		echo "${_cmdline}"
		return 0
	fi
	_log "No cmdline file found at [%s], trying to auto-generate one..." "${SBMGR_CMDLINE_PATH}" >&2

	# Determine root device and filesystem type
	_root_device="$(findmnt -n -o SOURCE / || true)"
	_root_fstype="$(findmnt -n -o FSTYPE / || true)"
	if [[ -z "${_root_device}" ]] || [[ -z "${_root_fstype}" ]]; then
		_log_fatal "Unable to determine root filesystem, please configure [%s] manually!" "${SBMGR_CMDLINE_PATH}"
	fi

	# Build root parameter based on determined device and filesystem
	if [[ "${_root_fstype}" == "zfs" ]]; then
		_root="ZFS=${_root_device}"
	else
		_root="${_root_device}"
	fi

	# Generate cmdline which probably should work in most cases
	echo "root=${_root} ro quiet"
	return 0
}

# Ensure sbmgr has been installed on system
function _sbmgr_ensure_install() {
	if ! _has_files \
		"${SBMGR_INSTALL_PATH}" \
		"${SBMGR_KEYS_PATH}/db.crt" \
		"${SBMGR_KEYS_PATH}/db.key" \
		"${SBMGR_KEYS_PATH}/db.esl" \
		"${SBMGR_KEYS_PATH}/db.auth" \
	; then
		_log_fatal "You must install sbmgr with [install] before managing kernel versions!"
	fi
}

# Generate unique Secure Boot keys locally on system
function _sbmgr_generate_secureboot_keys() {
	(
		local -r _path="${SBMGR_KEYS_PATH}"
		local _guid
		umask 0077

		# Ensure directory for storing keys exists
		if [[ ! -d "${_path}" ]]; then
			mkdir -p "${_path}"
		fi

		# Generate GUID for Secure Boot keys
		_has_files "${_path}/GUID.txt" || {
			_log "Generating new Secure Boot GUID for unique host keys..."
			_cmd_run uuidgen --random > "${_path}/GUID.txt"
		}
		_guid="$(cat "${_path}/GUID.txt")"
		_log "Using GUID for unique Secure Boot keys: ${_guid}"

		# Generate PK/KEK/DB with determined GUID
		_secureboot_generate_key "${_path}/PK" "Secure Boot Platform Key" "${_guid}"
		_secureboot_generate_key "${_path}/KEK" "Secure Boot Key Exchange Key" "${_guid}" "${_path}/PK"
		_secureboot_generate_key "${_path}/db" "Secure Boot Signature Database" "${_guid}" "${_path}/KEK"
	)
}

# Install systemd-boot on specified target
function _sbmgr_install_bootloader() {
	local _target _target_mp

	for _target in "${!SBMGR_TARGET_MOUNTS[@]}"; do
		_target_mp="${SBMGR_TARGET_MOUNTS[${_target}]}"

		# Use bootctl for installing/updating systemd-boot
		if [[ ! -f "${_target_mp}/${SYSTEMD_BOOT_PRIMARY_EFI}" ]]; then
			_log "Installing systemd-boot to target [%s]..." "${_target}"
			_cmd_run_silent bootctl install --graceful --path "${_target_mp}"
		else
			_log "Updating systemd-boot at target [%s]..." "${_target}"
			_cmd_run_silent bootctl update --graceful --path "${_target_mp}"
		fi

		# Sign and verify systemd-boot images
		_log "Signing systemd-boot images with own keys..."
		_secureboot_sign_and_verify_image "${_target_mp}/${SYSTEMD_BOOT_PRIMARY_EFI}"
		_secureboot_sign_and_verify_image "${_target_mp}/${SYSTEMD_BOOT_FALLBACK_EFI}"

		# Enforce systemd-boot configuration with secure values
		_log "Enforcing systemd-boot loader configuration..."
		cat >"${_target_mp}/loader/loader.conf" <<-EOF
		default ${SBMGR_IMAGE_PREFIX}-*
		timeout 3
		editor no
		auto-entries 1
		auto-firmware 1
		EOF
	done
}

# Install system-wide hooks for automatically triggering sbmgr
function _sbmgr_install_hooks() {
	# Ensure sbmgr has been installed permanently to system
	_has_files "${SBMGR_INSTALL_PATH}" \
		|| _log_fatal "Could not find sbmgr at install path: %s" "${SBMGR_INSTALL_PATH}"

	# Install hook for installing kernels
	_log "Installing hook for installing kernels at [%s]..." "${KERNEL_INSTALL_HOOK}"
	_cmd_run_silent mkdir -p "$(dirname "${KERNEL_INSTALL_HOOK}")"
	cat >"${KERNEL_INSTALL_HOOK}" <<-EOF
	#!/bin/sh
	set -e
	"${SBMGR_INSTALL_PATH}" install-kernel "\${1}"
	EOF
	_cmd_run_silent chmod +x "${KERNEL_INSTALL_HOOK}"

	# Install hook for removing kernels
	_log "Installing hook for removing kernels at [%s]..." "${KERNEL_REMOVE_HOOK}"
	_cmd_run_silent mkdir -p "$(dirname "${KERNEL_REMOVE_HOOK}")"
	cat >"${KERNEL_REMOVE_HOOK}" <<-EOF
	#!/bin/sh
	set -e
	"${SBMGR_INSTALL_PATH}" remove-kernel "\${1}"
	EOF
	_cmd_run_silent chmod +x "${KERNEL_REMOVE_HOOK}"

	# Install hook for initramfs updates
	_log "Installing hook for initramfs updates at [%s]..." "${INITRD_POST_UPDATE_HOOK}"
	_cmd_run_silent mkdir -p "$(dirname "${INITRD_POST_UPDATE_HOOK}")"
	cat >"${INITRD_POST_UPDATE_HOOK}" <<-EOF
	#!/bin/sh
	set -e
	"${SBMGR_INSTALL_PATH}" install-kernel "\${1}"
	EOF
	_cmd_run_silent chmod +x "${INITRD_POST_UPDATE_HOOK}"
}

# Install keytool on specified target for easy PK/KEK/db deployment
function _sbmgr_install_keytool() {
	local -r _signed_image_cache="${SBMGR_TMP_DIR}/KeyTool.signed.efi"
	local _target _target_mp

	for _target in "${!SBMGR_TARGET_MOUNTS[@]}"; do
		_target_mp="${SBMGR_TARGET_MOUNTS[${_target}]}"

		# Install KeyTool only if missing or unsigned
		_log "Installing KeyTool to target [%s]..." "${_target}"
		if ! _secureboot_verify_image "${_target_mp}/EFI/KeyTool.efi"; then
			# Store signed KeyTool copy in temporary directory to avoid signing once per target
			if ! _secureboot_verify_image "${_signed_image_cache}"; then
				_log "Signing KeyTool image once for current and other targets..."
				_secureboot_sign_image "${KEYTOOL_EFI_IMAGE}" "${_signed_image_cache}"
			else
				_log "Reusing signed KeyTool image [%s]..." "${_signed_image_cache}"
			fi

			# Copy signed version over to target
			_cmd_run_silent cp -av "${_signed_image_cache}" "${_target_mp}/EFI/KeyTool.efi"
		fi

		# Generate systemd-boot launcher entry
		_log "Configuring systemd-boot launcher entry for KeyTool on target [%s]..." "${_target}"
		cat >"${_target_mp}/loader/entries/keytool.conf" <<-'EOF'
		title KeyTool
		efi /EFI/KeyTool.efi
		EOF
	done
}

# Installs this script to a permanent location for usage with hooks
function _sbmgr_install_script() {
	local _script_path

	# Determine current script and copy to install path if not equal
	_script_path="$(realpath "${0}")"
	if [[ "${_script_path}" != "${SBMGR_INSTALL_PATH}" ]]; then
		_log "Installing sbmgr from [%s] to [%s]" "${_script_path}" "${SBMGR_INSTALL_PATH}"
		_cmd_run_silent cp -av "${_script_path}" "${SBMGR_INSTALL_PATH}"
	fi

	# Ensure script is always executable to avoid carnage
	_cmd_run_silent chmod +x "${SBMGR_INSTALL_PATH}"
}

# Builds, signs and deploys a specific kernel version using EFISTUB
function _sbmgr_kernel_deploy() {
	local _version="${1}"
	local _target _target_mp
	local _os_release _kernel_path _cmdline  _initrd_path

	# Determine cmdline for kernel
	_kernel_cmdline="$(_sbmgr_determine_kernel_cmdline)"
	_log "Kernel command line: ${_kernel_cmdline}"

	# Generate custom os-release which contains kernel version
	_os_release="$(grep -Ev '^VERSION_ID=' "${OS_RELEASE_PATH}")"
	_os_release="$(printf '%s\n' "${_os_release}" "VERSION_ID=\"${_version}")\""

	# Generate initrd and kernel paths using configured patterns
	# shellcheck disable=SC2059
	_initrd_path="$(printf "${LINUX_INITRD_PATH_PATTERN}" "${_version}")"
	# shellcheck disable=SC2059
	_kernel_path="$(printf "${LINUX_KERNEL_PATH_PATTERN}" "${_version}")"

	# Build unified EFISTUB image
	_efistub_build_image \
		"${_os_release}" "${_initrd_path}" \
		"${_kernel_path}" "${_kernel_cmdline}" \
		"${SBMGR_TMP_DIR}/${SBMGR_IMAGE_PREFIX}-${_version}.efi"

	# Sign and verify unified EFISTUB image
	_secureboot_sign_and_verify_image \
		"${SBMGR_TMP_DIR}/${SBMGR_IMAGE_PREFIX}-${_version}.efi" \
		"${SBMGR_TMP_DIR}/${SBMGR_IMAGE_PREFIX}-${_version}.signed.efi"

	# Deploy signed image to all targets
	for _target in "${!SBMGR_TARGET_MOUNTS[@]}"; do
		_target_mp="${SBMGR_TARGET_MOUNTS[${_target}]}"
		_log "Installing EFISTUB image for kernel version [%s] to target [%s]" \
			"${_version}" "${_target}"

		# Create folder for EFISTUB images and copy file into it
		_cmd_run_silent mkdir -p "${_target_mp}/EFI/Linux"
		_cmd_run_silent cp -av \
			"${SBMGR_TMP_DIR}/${SBMGR_IMAGE_PREFIX}-${_version}.signed.efi" \
			"${_target_mp}/EFI/Linux/${SBMGR_IMAGE_PREFIX}-${_version}.efi"
	done
}

# Removes a specific kernel version from all targets
function _sbmgr_kernel_remove() {
	local _version="${1}"
	local _target _target_mp

	# Remove image from all targets
	for _target in "${!SBMGR_TARGET_MOUNTS[@]}"; do
		_target_mp="${SBMGR_TARGET_MOUNTS[${_target}]}"
		_log "Removing EFISTUB image for kernel version [%s] from target [%s]" \
			"${_version}" "${_target}"

		_cmd_run_silent rm -f "${_target_mp}/EFI/Linux/${SBMGR_IMAGE_PREFIX}-${_version}.efi"
	done
}

# Mount configured targets into temporary folders by UUID
function _sbmgr_mount_targets() {
	local _target _target_mp _target_uuid

	for _target in "${SBMGR_TARGETS[@]}"; do
		# Determine uppercased UUID of target
		_target_uuid="$(blkid -s UUID -o value "${_target}")"
		_target_uuid="${_target_uuid^^}"
		if [[ -z "${_target_uuid}" ]]; then
			_log_fatal "Unable to determine UUID of target [%s]" "${_target}"
		fi

		# Ensure UUID matches VFAT-UUID pattern
		if [[ ! "${_target_uuid}" =~ ^[0-9A-F]{4}-[0-9A-F]{4}$ ]]; then
			_log_fatal "Unexpected UUID [%s] for target [%s], does not match pattern XXXX-XXXX" "${_target_uuid}" "${_target}"
		fi

		# Prepare temporary mountpoint for target
		_target_mp="${SBMGR_MOUNTS_PATH}/${_target_uuid}"
		SBMGR_TARGET_MOUNTS["${_target}"]="${_target_mp}"
		mkdir -p "${_target_mp}"

		# Mount target into specified directory
		_log "Mounting [%s] to [%s] for synchronization..." "${_target}" "${_target_mp}"
		_cmd_run_silent mount -t vfat "${_target}" "${_target_mp}"
	done
}

# Creates a secure temporary directory restricted to current user
function _sbmgr_prepare_tmpdir() {
	# Create temporary directory with secure umask
	SBMGR_TMP_DIR="$(umask 0077; mktemp -d -t sbmgr-XXXXXXXXXX)"
	declare -gr SBMGR_TMP_DIR

	# Ensure temporary directory has been created
	if [[ ! -d "${SBMGR_TMP_DIR}" ]]; then
		_log_fatal "Could not create secure temporary directory with mktemp"
	fi
}

# Re-executes the current script in private mount namespace
function _sbmgr_reexec_mountns() {
	if [[ -z "${SBMGR_MOUNTNS:-}" ]]; then
		_log "Re-executing in private mount namespace..."

		# Set environment variable to indicate running in mountns, then re-execute
		export SBMGR_MOUNTNS=1
		unshare --mount --propagation private "${0}" "${@}"

		# Manually launch cleanup handler with suppressed output, then exit
		_sbmgr_cleanup >/dev/null
	fi
}

function _sbmgr_remove_secureboot_keys() {
	local _target _target_mp

	for _target in "${!SBMGR_TARGET_MOUNTS[@]}"; do
		_target_mp="${SBMGR_TARGET_MOUNTS[${_target}]}"

		_log "Removing Secure Boot keys from target [%s]..." "${_target}"
		_cmd_run_silent rm -rf "${_target_mp}/SecureBoot"
	done
}

# Synchronize keys to targets for deployment
function _sbmgr_sync_secureboot_keys() {
	local _target _target_mp

	for _target in "${!SBMGR_TARGET_MOUNTS[@]}"; do
		_target_mp="${SBMGR_TARGET_MOUNTS[${_target}]}"

		_log "Synchronizing Secure Boot keys to target [%s]..." "${_target}"
		_cmd_run_silent mkdir -p "${_target_mp}/SecureBoot"
		_cmd_run_silent rsync \
			-vhr --delete --delete-excluded \
			--include "*.cer" --include "*.esl" --include "*.auth" \
			--exclude "*" \
			"${SBMGR_KEYS_PATH}/" "${_target_mp}/SecureBoot"
	done
}

# Removes systemd-boot from all targets
function _sbmgr_uninstall_bootloader() {
	local _target _target_mp

	for _target in "${!SBMGR_TARGET_MOUNTS[@]}"; do
		_target_mp="${SBMGR_TARGET_MOUNTS[${_target}]}"

		_log "Removing systemd-boot from target [%s]..." "${_target}"
		if [[ -f "${_target_mp}/${SYSTEMD_BOOT_PRIMARY_EFI}" ]]; then
			_cmd_run_silent bootctl remove --path "${_target_mp}"
		fi
		_cmd_run_silent rm -rf "${_target_mp}/loader"
	done
}

# Removes all hooks installed by sbmgr
function _sbmgr_uninstall_hooks() {
	_log "Uninstalling sbmgr hooks from system..."
	_cmd_run_silent rm -f \
		"${KERNEL_INSTALL_HOOK}" \
		"${KERNEL_REMOVE_HOOK}" \
		"${INITRD_POST_UPDATE_HOOK}"
}

# Removes KeyTool from all targets
function _sbmgr_uninstall_keytool() {
	local _target _target_mp

	for _target in "${!SBMGR_TARGET_MOUNTS[@]}"; do
		_target_mp="${SBMGR_TARGET_MOUNTS[${_target}]}"

		_log "Removing KeyTool from target [%s]..." "${_target}"
		_cmd_run_silent rm -f \
			"${_target_mp}/EFI/KeyTool.efi" \
			"${_target_mp}/loader/entries/keytool.conf"
	done
}

# Removes sbmgr from system while leaving configuration
function _sbmgr_uninstall_script() {
	_log "Removing sbmgr script [%s] from system..." "${SBMGR_INSTALL_PATH}"
	_cmd_run_silent rm -f "${SBMGR_INSTALL_PATH}"
}

# Joins an array with the given separator
function _array_join() {
	local -r _separator="${1}"; shift
	local -ra _array=("${@}")

	printf "%s${_separator}" "${_array[@]}"
}

# Executes command with error reporting
function _cmd_run() {
	local -ra _args=("${@}")

	if ! _output="$("${_args[@]}" 2>&1)"; then
		_log_fatal "Command execution [%s] failed:\n%s" "${_args[0]}" "${_output}"
	else
		echo "${_output}"
	fi
}

# Silently executes command with error reporting
function _cmd_run_silent() {
	_cmd_run "${@}" >/dev/null
}

# Generates an unified EFISTUB image with kernel, initrd, cmdline and os-release
function _efistub_build_image() {
	local _os_release="${1}"
	local _initrd_path="${2}"
	local _kernel_path="${3}"
	local _kernel_cmdline="${4}"
	local _output_path="${5}"

	_log "Building EFISTUB kernel image with [%s]+[%s] as [%s]..." \
		"$(basename "${_kernel_path}")" \
		"$(basename "${_initrd_path}")" \
		"${_output_path}"

	_cmd_run_silent objcopy \
		--add-section .osrel=<(printf '%s' "${_os_release}") --change-section-vma .osrel=0x20000 \
		--add-section .cmdline=<(printf '%s' "${_kernel_cmdline}") --change-section-vma .cmdline=0x30000 \
		--add-section .linux="${_kernel_path}" --change-section-vma .linux=0x2000000 \
		--add-section .initrd="${_initrd_path}" --change-section-vma .initrd=0x3000000 \
		"${EFISTUB_EFI_IMAGE}" "${_output_path}"
}

# Ensures that all argument are valid commands
function _ensure_commands() {
	local -ra _commands=("${@}")
	local _command

	for _command in "${_commands[@]}"; do
		if ! command -v "${_command}" &>/dev/null; then
			_log_fatal "Missing required command: ${_command}"
		fi
	done
}

# Checks if all the given arguments exist as files
function _has_files() {
	local -ra _files=("${@}")
	local _file

	for _file in "${_files[@]}"; do
		if [[ ! -f "${_file}" ]]; then
			return 1
		fi
	done

	return 0
}

# Prints a formatted and prefixed log message to stdout
function _log() {
	local -r _format="${1}"; shift
	# shellcheck disable=SC2059
	printf "[sbmgr] ${_format}\n" "${@}"
}

# Prints a formatted and prefixed log message to stderr and exits with code 1
function _log_fatal() {
	_log "${@}" >&2
	exit 1
}

# Generates a Secure Boot key with the specified parameters
# Such a key consists of: certificate with private key, signature list, auth key
function _secureboot_generate_key() {
	local -r _path="${1}"
	local -r _name="${2}"
	local -r _guid="${3}"
	local -r _signer_path="${4:-${_path}}" # default to self-signed

	_log "Generating key [%s] if missing..." "${_name}"

	# Generate PEM certificate with private key if missing
	_has_files "${_path}.crt" "${_path}.key" || {
		_cmd_run_silent openssl req \
			-newkey rsa:4096 -nodes -keyout "${_path}.key" \
			-new -x509 -sha256 -days 3650 -out "${_path}.crt" \
			-subj "/CN=${_name} - $(hostname -f)/"
		rm -f "${_path}.cer" "${_path}.esl" "${_path}.auth" &>/dev/null
	}

	# Convert certificate from PEM into DER if missing
	_has_files "${_path}.cer" || {
		_cmd_run_silent openssl x509 \
			-inform PEM -in "${_path}.crt" \
			-outform DER -out "${_path}.cer"
		rm -f "${_path}.esl" "${_path}.auth" &>/dev/null
	}

	# Convert certificate into EFI signature list if missing
	_has_files "${_path}.esl" || {
		_cmd_run_silent cert-to-efi-sig-list \
			-g "${_guid}" "${_path}.crt" "${_path}.esl"
		rm -f "${_path}.auth" &>/dev/null
	}

	# Sign EFI signature list with specified signer key
	_has_files "${_path}.auth" || {
		_cmd_run_silent sign-efi-sig-list \
			-g "${_guid}" \
			-c "${_signer_path}.crt" -k "${_signer_path}.key" \
			PK "${_path}.esl" "${_path}.auth"
	}
}

# Signs and verifies an EFI image with the specified signing key
# If no signer is specified, this uses the "db" key by default
function _secureboot_sign_and_verify_image() {
	local -r _input_path="${1}"
	local -r _output_path="${2:-${1}}"
	local -r _signer_key_path="${3:-${SBMGR_KEYS_PATH}/db}"

	if ! _secureboot_verify_image "${_input_path}" "${_signer_key_path}"; then
		_secureboot_sign_image "${_input_path}" "${_output_path}" "${_signer_key_path}"
		_cmd_run_silent sbverify --cert "${_signer_key_path}.crt" "${_output_path}"
	fi
}

# Signs an EFI image with the specified signing key
# If no signer is specified, this uses the "db" key by default
function _secureboot_sign_image() {
	local -r _input_path="${1}"
	local -r _output_path="${2:-${1}}"
	local -r _signer_key_path="${3:-${SBMGR_KEYS_PATH}/db}"

	if [[ "${_input_path}" != "${_output_path}" ]]; then
		_log "Signing EFI image [%s] as [%s] with [%s]..." "${_input_path}" "${_output_path}" "${_signer_key_path}"
	else
		_log "Signing EFI image [%s] with [%s]..." "${_input_path}" "${_signer_key_path}"
	fi

	_cmd_run_silent sbsign "${_input_path}" \
		--cert "${_signer_key_path}.crt" --key "${_signer_key_path}.key" \
		--output "${_output_path}"
}

# Verifies if the given EFI image has been signed by the specified signing key
# If no signer is specified, this uses the "db" key by default
function _secureboot_verify_image() {
	local -r _image_path="${1}"
	local -r _signer_key_path="${2:-${SBMGR_KEYS_PATH}/db}"

	if sbverify --cert "${_signer_key_path}.crt" "${_image_path}" &>/dev/null; then
		return 0
	else
		return 1
	fi
}

# Main entrypoint
main "${@}"
