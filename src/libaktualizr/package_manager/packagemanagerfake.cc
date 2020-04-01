#include "packagemanagerfake.h"
#include "packagemanagerfactory.h"

#include "utilities/fault_injection.h"

AUTO_REGISTER_PACKAGE_MANAGER(PACKAGE_MANAGER_NONE, PackageManagerFake);

#include <McuUpdate/McuUpdate.h>
extern "C" {
#include <OTAUpdate/update.h>
}
#include <archive.h>
#include <archive_entry.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h> 

Json::Value PackageManagerFake::getInstalledPackages() const {
  Json::Value packages(Json::arrayValue);
  Json::Value package;
  package["name"] = "fake-package";
  package["version"] = "1.0";
  packages.append(package);
  return packages;
}

Uptane::Target PackageManagerFake::getCurrent() const {
  boost::optional<Uptane::Target> current_version;
  storage_->loadPrimaryInstalledVersions(&current_version, nullptr);

  if (!!current_version) {
    return *current_version;
  }

  return Uptane::Target::Unknown();
}

data::InstallationResult PackageManagerFake::install(const Uptane::Target& target) const {
  (void)target;

#if defined UPDATE_ARCHIVE

  // TODO: Better refactor function, create Utility?
  // Need RAM ? -> HUGE PROBLEM !!

  struct archive *archive_reader = archive_read_new();

  std::unique_ptr<StorageTargetRHandle> target_data_uptr;

  std::function<ssize_t(archive *, void *, const void **)> callback_func_read =
      [&target_data_uptr](archive *, void *_client_data, const void **_buffer) {
        return (ssize_t)target_data_uptr->rread((uint8_t *)*_buffer, (size_t)10 * 1024 * 1024);
      };

  if (archive_read_support_filter_all(archive_reader) != ARCHIVE_OK) {
    return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, "Archive Extraction Error");
  } else if (archive_read_support_format_all(archive_reader) != ARCHIVE_OK) {
    return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, "Archive Extraction Error");
  } else if (archive_read_set_read_callback(archive_reader, (archive_read_callback *)&callback_func_read)) {
    return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, "Archive Extraction Error");
  } else if (archive_read_open1(archive_reader) != ARCHIVE_OK) {
    return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, "Archive Extraction Error");
  } else {
    target_data_uptr = storage_->openTargetFile(target);

    if (target_data_uptr->isPartial()) {
      return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, "Internal Library Error");
    } else {
      struct archive *archive_writer = archive_write_disk_new();
      if (archive_write_disk_set_standard_lookup(archive_writer) != ARCHIVE_OK) {
        return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, "Archive Extraction Error");
      } else {
        struct archive_entry *archive_entry;

        int archive_error = archive_read_next_header(archive_reader, &archive_entry);

        do {
          // !! NO UNMANAGED CASE !! - Got it?!
          switch (archive_error) {
            case ARCHIVE_EOF: {
              // TODO: installation
              break;
            }
            case ARCHIVE_OK: {
              // Write it

              std::string new_path = "/tmp/", old_path;

              archive_entry_copy_pathname(archive_entry, old_path.data());

              new_path.append(old_path.substr(old_path.rfind('/')));

              archive_entry_set_pathname(archive_entry, new_path.c_str());

              int archive_entry_size_value = archive_entry_size(archive_entry);

              if (archive_entry_size_value <= 0) {
                return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, "Archive Extraction Error");
              }

              struct archive *archive_writer = archive_write_new();

              int archive_entry_error = archive_write_header(archive_writer, archive_entry);

              switch (archive_entry_error) {
                case ARCHIVE_OK:  // Wrote HEADER
                {
                  do {
                    const void *buffer;
                    size_t size_of_block, size_of_block;
                    int64_t offset;

                    archive_entry_error = archive_read_data_block(archive_reader, &buffer, &size_of_block, &offset);

                    if (archive_entry_error != ARCHIVE_OK) {
                      return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed,
                                                      "Archive Extraction Error");
                    }

                    size_of_block = archive_write_data_block(archive_writer, buffer, size_of_block, offset);

                    if (size_of_block < 0) {
                      return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed,
                                                      "Archive Extraction Error");
                    } else if (archive_entry_error == ARCHIVE_EOF) {
                      break;
                    } else if (archive_entry_error < ARCHIVE_OK) {
                      return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed,
                                                      "Archive Extraction Error");
                    }

                  } while (archive_entry_error == ARCHIVE_OK);

                  break;
                }
                case ARCHIVE_RETRY:
                case ARCHIVE_WARN:
                case ARCHIVE_FAILED:
                case ARCHIVE_FATAL: {
                  return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed,
                                                  "Archive Extraction Error");
                  break;
                }
                case ARCHIVE_EOF: {
                  break;
                }
              }
              break;
            }
            case ARCHIVE_RETRY:
            case ARCHIVE_WARN:
            case ARCHIVE_FAILED:
            case ARCHIVE_FATAL: {
              return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, "Archive Extraction Error");
              break;
            }
          }

        } while (archive_error == ARCHIVE_OK);
      }

      archive_write_close(archive_writer);
      archive_write_free(archive_writer);
    }
  }
  archive_read_close(archive_reader);
  archive_read_free(archive_reader);

  uint8_t availUpdates;
  LicuPackageInfo_t updInfo;
  LicuCurrentInfo_t curInfo;
  int8_t retVal;
  uint8_t simulationMode = 0;
  updInfo.UpdateType = UPDATE_OTA_TMP;
  McuUpdateInit();

  availUpdates = UpdateDetectAvailable();
#else // defined UPDATE_ARCHIVE
  fprintf(stdout, " ----> MOUNT UPDATE\n");
  const char *storage_path = "/mnt/mmctlm/OTAManager/images/";
  const char *TARGET_MOUNT_PATH = "/mnt/otaimg";
  const char *TARGET_MOUNT_FSTYPE = "ext3";
  std::string path_target = storage_path;
  std::string file_name = target.sha256Hash();
  boost::to_upper(file_name);
  path_target.append(file_name);
  fprintf(stdout, " ----> Path Target: %s\n", path_target.c_str());
  if (boost::filesystem::exists(TARGET_MOUNT_PATH)) {
    // Nothig to do;
    fprintf(stdout, " ----> exists\n");
  } else {
      boost::filesystem::create_directory(TARGET_MOUNT_PATH);
      fprintf(stdout, " ----> create_directory\n");
  }
  
  if (boost::filesystem::is_empty(TARGET_MOUNT_PATH)) {
    // Nothig to do;  
    fprintf(stdout, " ----> is_empty\n");
  } else {
    return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, "File Generic Error");
  }

  std::string cmd = "mount " + path_target + " " + std::string(TARGET_MOUNT_PATH);
  fprintf(stdout, " ----> Mounting command: %s\n", cmd.c_str());
  //int mount_res = ::mount(path_target.c_str(), TARGET_MOUNT_PATH, TARGET_MOUNT_FSTYPE, MS_MGC_VAL | MS_RDONLY | MS_NOSUID, "");
  int mount_res = std::system(cmd.c_str());
  int e = errno;
  fprintf(stdout, " ----> mount: %d\n", mount_res);
  if (mount_res != 0) {
      fprintf(stdout, " ----> ERRNO: %d\n", e);
      return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, "File Generic Error");
  }
  fprintf(stdout, " ----> After If\n");
  uint8_t availUpdates;
  LicuPackageInfo_t updInfo;
  memset(&updInfo, 0x00, sizeof(LicuPackageInfo_t));
  LicuCurrentInfo_t curInfo;
  int8_t retVal;
  uint8_t simulationMode = 0;
  updInfo.UpdateType = UPDATE_OTA_IMG;
  /*  
   * strcpy(updInfo.UpdateStartCommand, "sync");
   * strcpy(updInfo.UpdateFinishCommand, "sync");
   */
  McuUpdateInit();

  availUpdates = UpdateDetectAvailable();
  fprintf(stdout, " ----> UpdateType: %d\n", updInfo.UpdateType);
  fprintf(stdout, " ----> Avail: %u\n", availUpdates);
#endif // defined UPDATE_ARCHIVE

#if 1

  if (availUpdates & LICU_UPDATE_PRESENT || availUpdates & LICU_UPDATE_OTA_IMG_PRESENT || availUpdates & LICU_UPDATE_OTA_TMP_PRESENT)
  {
    ///
    /// Get Update Info
    ///
    fprintf(stdout, " ----> POINTER CPP: %p\n", &updInfo);
    retVal = UpdateLicuGetPackageInfo(&updInfo);
    fprintf(stdout, " ----> UpdateLicuGetPackageInfo: %d\n", retVal);
    UpdateLicuPrintPackageInfo(updInfo);

    if (retVal != UPD_OK) {
      McuUpdateClose();
      return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, "Installation Generic Error");
    }
    
    ///
    /// Get Current Info
    ///
    retVal = UpdateLicuGetCurrentInfo(&curInfo);
    fprintf(stdout, " ----> UpdateLicuGetCurrentInfo: %d\n", retVal);

    if (retVal != UPD_OK) {  
      McuUpdateClose();
      return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, "Installation Generic Error");
    }
    UpdateLicuPrintCurrentInfo(curInfo);
    fprintf(stdout, " ----> UpdateLicuPrintCurrentInfo\n");

    if (retVal != UPD_OK) {
      McuUpdateClose();
      return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, "Installation Generic Error");
    }
    
    UpdateLicuSetSimulationMode(simulationMode);
    fprintf(stdout, " ----> UpdateLicuSetSimulationMode: %d\n", simulationMode);

    ///
    /// Start ICU Update
    ///

    retVal = UpdateLicuStart(curInfo, updInfo);
    fprintf(stdout, " ----> UpdateLicuStart: %d\n", retVal);
    if (retVal != UPD_OK) {
      McuUpdateClose();
      return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, "Installation Generic Error");
    }

    ///
    /// Update Licu WaitEnd
    ///
    retVal = UpdateLicuWaitEnd();
    fprintf(stdout, " ----> UpdateLicuWaitEnd: %d\n", retVal);
    if (retVal != UPD_OK) {
      McuUpdateClose();
      return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, "Installation Generic Error");
    }
  } else {
    McuUpdateClose();
    return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, "Update Folder not Found");
  }

  McuUpdateClose();
  
  return data::InstallationResult(data::ResultCode::Numeric::kOk, "Installing package was successful");

#else
  // fault injection: only enabled with FIU_ENABLE defined
  if (fiu_fail("fake_package_install") != 0) {
    std::string failure_cause = fault_injection_last_info();
    if (failure_cause.empty()) {
      return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, "");
    }
    LOG_DEBUG << "Causing installation failure with message: " << failure_cause;
    return data::InstallationResult(data::ResultCode(data::ResultCode::Numeric::kInstallFailed, failure_cause), "");
  }

  if (config.fake_need_reboot) {
    // set reboot flag to be notified later
    if (bootloader_ != nullptr) {
      bootloader_->rebootFlagSet();
    }
    return data::InstallationResult(data::ResultCode::Numeric::kNeedCompletion, "Application successful, need reboot");
  }

  return data::InstallationResult(data::ResultCode::Numeric::kOk, "Installing package was successful");
#endif
}

void PackageManagerFake::completeInstall() const {
  LOG_INFO << "Emulating a system reboot";
  bootloader_->reboot(true);
}

data::InstallationResult PackageManagerFake::finalizeInstall(const Uptane::Target& target) {
  if (config.fake_need_reboot && !bootloader_->rebootDetected()) {
    return data::InstallationResult(data::ResultCode::Numeric::kNeedCompletion,
                                    "Reboot is required for the pending update application");
  }

  boost::optional<Uptane::Target> pending_version;
  storage_->loadPrimaryInstalledVersions(nullptr, &pending_version);

  if (!pending_version) {
    throw std::runtime_error("No pending update, nothing to finalize");
  }

  data::InstallationResult install_res;

  if (target.MatchTarget(*pending_version)) {
    if (fiu_fail("fake_install_finalization_failure") != 0) {
      const std::string failure_cause = fault_injection_last_info();
      if (failure_cause.empty()) {
        install_res = data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, "");
      } else {
        install_res =
            data::InstallationResult(data::ResultCode(data::ResultCode::Numeric::kInstallFailed, failure_cause),
                                     "Failed to finalize the pending update installation");
      }
    } else {
      install_res = data::InstallationResult(data::ResultCode::Numeric::kOk, "Installing fake package was successful");
    }

  } else {
    install_res =
        data::InstallationResult(data::ResultCode::Numeric::kInternalError, "Pending and new target do not match");
  }

  if (config.fake_need_reboot) {
    bootloader_->rebootFlagClear();
  }
  return install_res;
}

bool PackageManagerFake::fetchTarget(const Uptane::Target& target, Uptane::Fetcher& fetcher, const KeyManager& keys,
                                     FetcherProgressCb progress_cb, const api::FlowControlToken* token) {
  // fault injection: only enabled with FIU_ENABLE defined. Note that all
  // exceptions thrown in PackageManagerInterface::fetchTarget are caught by a
  // try in the same function, so we can only emulate the warning and return
  // value.
  if (fiu_fail("fake_package_download") != 0) {
    const std::string failure_cause = fault_injection_last_info();
    if (!failure_cause.empty()) {
      LOG_WARNING << "Error while downloading a target: " << failure_cause;
    } else {
      LOG_WARNING << "Error while downloading a target: forced failure";
    }
    return false;
  }

  return PackageManagerInterface::fetchTarget(target, fetcher, keys, progress_cb, token);
}


