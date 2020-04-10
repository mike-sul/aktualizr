#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <boost/process.hpp>

#include "aktualizr_secondary_file.h"
//#include "aktualizr_secondary_factory.h"
#include "crypto/keymanager.h"
#include "test_utils.h"
#include "update_agent.h"
#include "update_agent_file.h"
#include "uptane_repo.h"
#include "utilities/utils.h"

using ::testing::NiceMock;

class UpdateAgentMock : public FileUpdateAgent {
 public:
  UpdateAgentMock(boost::filesystem::path target_filepath, std::string target_name)
      : FileUpdateAgent(std::move(target_filepath), std::move(target_name)) {
    ON_CALL(*this, receiveData).WillByDefault([this](const Uptane::Target& target, const uint8_t* data, size_t size) {
      return FileUpdateAgent::receiveData(target, data, size);
    });
    ON_CALL(*this, install).WillByDefault([this](const Uptane::Target& target) {
      return FileUpdateAgent::install(target);
    });
  }

  MOCK_METHOD(data::ResultCode::Numeric, receiveData, (const Uptane::Target& target, const uint8_t* data, size_t size));
  MOCK_METHOD(data::ResultCode::Numeric, install, (const Uptane::Target& target));
};

class AktualizrSecondaryWrapper {
 public:
  AktualizrSecondaryWrapper() {
    AktualizrSecondaryConfig config;
    config.pacman.type = PACKAGE_MANAGER_NONE;

    config.storage.path = _storage_dir.Path();
    config.storage.type = StorageType::kSqlite;

    _storage = INvStorage::newStorage(config.storage);

    update_agent = std::make_shared<NiceMock<UpdateAgentMock>>(config.storage.path / "firmware.txt", "");

    _secondary = std::make_shared<AktualizrSecondaryFile>(config, _storage, update_agent);
  }

  std::shared_ptr<AktualizrSecondaryFile>& operator->() { return _secondary; }

  Uptane::Target getPendingVersion() const {
    boost::optional<Uptane::Target> pending_target;

    _storage->loadInstalledVersions(_secondary->serial().ToString(), nullptr, &pending_target);
    return *pending_target;
  }

  std::string hardwareID() const { return _secondary->hwID().ToString(); }

  std::string serial() const { return _secondary->serial().ToString(); }

  boost::filesystem::path targetFilepath() const {
    return _storage_dir.Path() / AktualizrSecondaryFile::FileUpdateDefaultFile;
  }

  std::shared_ptr<NiceMock<UpdateAgentMock>> update_agent;

 private:
  TemporaryDirectory _storage_dir;
  std::shared_ptr<AktualizrSecondaryFile> _secondary;
  std::shared_ptr<INvStorage> _storage;
};

class UptaneRepoWrapper {
 public:
  UptaneRepoWrapper() { _uptane_repo.generateRepo(KeyType::kED25519); }

  Metadata addImageFile(const std::string& targetname, const std::string& hardware_id, const std::string& serial,
                        size_t size = 2049, bool add_and_sign_target = true, bool add_invalid_images = false,
                        size_t delta = 2) {
    const auto image_file_path = _root_dir / targetname;
    generateRandomFile(image_file_path, size);

    _uptane_repo.addImage(image_file_path, targetname, hardware_id, "", Delegation());
    if (add_and_sign_target) {
      _uptane_repo.addTarget(targetname, hardware_id, serial, "");
      _uptane_repo.signTargets();
    }

    if (add_and_sign_target && add_invalid_images) {
      const auto smaller_image_file_path = image_file_path.string() + ".smaller";
      const auto bigger_image_file_path = image_file_path.string() + ".bigger";
      const auto broken_image_file_path = image_file_path.string() + ".broken";

      boost::filesystem::copy(image_file_path, smaller_image_file_path);
      boost::filesystem::copy(image_file_path, bigger_image_file_path);
      boost::filesystem::copy(image_file_path, broken_image_file_path);

      if (!boost::filesystem::exists(smaller_image_file_path)) {
        LOG_ERROR << "File does not exists: " << smaller_image_file_path;
      }

      boost::filesystem::resize_file(smaller_image_file_path, size - delta);
      boost::filesystem::resize_file(bigger_image_file_path, size + delta);

      std::ofstream broken_image{broken_image_file_path,
                                 std::ios_base::in | std::ios_base::out | std::ios_base::ate | std::ios_base::binary};
      unsigned char data_to_inject[]{0xFF};
      broken_image.seekp(-sizeof(data_to_inject), std::ios_base::end);
      broken_image.write(reinterpret_cast<const char*>(data_to_inject), sizeof(data_to_inject));
      broken_image.close();
    }

    return getCurrentMetadata();
  }

  Uptane::RawMetaPack getCurrentMetadata() const {
    Uptane::RawMetaPack metadata;

    boost::filesystem::load_string_file(_director_dir / "root.json", metadata.director_root);
    boost::filesystem::load_string_file(_director_dir / "targets.json", metadata.director_targets);

    boost::filesystem::load_string_file(_imagerepo_dir / "root.json", metadata.image_root);
    boost::filesystem::load_string_file(_imagerepo_dir / "timestamp.json", metadata.image_timestamp);
    boost::filesystem::load_string_file(_imagerepo_dir / "snapshot.json", metadata.image_snapshot);
    boost::filesystem::load_string_file(_imagerepo_dir / "targets.json", metadata.image_targets);

    return metadata;
  }

  std::string getTargetImagePath(const std::string& targetname) const { return (_root_dir / targetname).string(); }

  void refreshRoot(Uptane::RepositoryType repo) { _uptane_repo.refresh(repo, Uptane::Role::Root()); }

 private:
  static void generateRandomFile(const boost::filesystem::path& filepath, size_t size) {
    std::ofstream file{filepath.string(), std::ofstream::binary};

    if (!file.is_open() || !file.good()) {
      throw std::runtime_error("Failed to create a file: " + filepath.string());
    }

    const unsigned char symbols[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv";
    unsigned char cur_symbol;

    for (unsigned int ii = 0; ii < size; ++ii) {
      cur_symbol = symbols[rand() % sizeof(symbols)];
      file.put(cur_symbol);
    }

    file.close();
  }

 private:
  TemporaryDirectory _root_dir;
  boost::filesystem::path _director_dir{_root_dir / "repo/director"};
  boost::filesystem::path _imagerepo_dir{_root_dir / "repo/repo"};
  UptaneRepo _uptane_repo{_root_dir.Path(), "", ""};
  Uptane::DirectorRepository _director_repo;
};

class SecondaryTest : public ::testing::Test {
 protected:
  SecondaryTest() : _update_agent(*(_secondary.update_agent)) {
    _uptane_repo.addImageFile(_default_target, _secondary->hwID().ToString(), _secondary->serial().ToString(),
                              target_size, true, true, inavlid_target_size_delta);
  }

  std::vector<Uptane::Target> getCurrentTargets() {
    auto targets = Uptane::Targets(Utils::parseJSON(_uptane_repo.getCurrentMetadata().director_targets));
    return targets.getTargets(_secondary->serial(), _secondary->hwID());
  }

  Uptane::Target getDefaultTarget() {
    auto targets = getCurrentTargets();
    EXPECT_GT(targets.size(), 0);
    return targets[0];
  }

  Uptane::Hash getDefaultTargetHash() {
    return Uptane::Hash(Uptane::Hash::Type::kSha256, getDefaultTarget().sha256Hash());
  }

  data::ResultCode::Numeric sendImageFile(std::string target_name = _default_target) {
    auto image_path = _uptane_repo.getTargetImagePath(target_name);
    size_t total_size = boost::filesystem::file_size(image_path);

    std::ifstream file{image_path};

    uint8_t buf[send_buffer_size];
    size_t read_and_send_data_size = 0;

    while (read_and_send_data_size < total_size) {
      auto read_bytes = file.readsome(reinterpret_cast<char*>(buf), sizeof(buf));
      if (read_bytes < 0) {
        file.close();
        return data::ResultCode::Numeric::kGeneralError;
      }

      auto result = _secondary->receiveData(buf, read_bytes);
      if (result != data::ResultCode::Numeric::kOk) {
        file.close();
        return result;
      }
      read_and_send_data_size += read_bytes;
    }

    file.close();

    data::ResultCode::Numeric result{data::ResultCode::Numeric::kGeneralError};
    if (read_and_send_data_size == total_size) {
      result = data::ResultCode::Numeric::kOk;
    }

    return result;
  }

 protected:
  static constexpr const char* const _default_target{"default-target"};
  static constexpr const char* const _bigger_target{"default-target.bigger"};
  static constexpr const char* const _smaller_target{"default-target.smaller"};
  static constexpr const char* const _broken_target{"default-target.broken"};

  static const size_t target_size{2049};
  static const size_t inavlid_target_size_delta{2};
  static const size_t send_buffer_size{1024};

  AktualizrSecondaryWrapper _secondary;
  UptaneRepoWrapper _uptane_repo;
  NiceMock<UpdateAgentMock>& _update_agent;
  TemporaryDirectory _image_dir;
};

class SecondaryTestNegative : public ::testing::Test,
                              public ::testing::WithParamInterface<std::pair<Uptane::RepositoryType, Uptane::Role>> {
 public:
  SecondaryTestNegative() : _update_agent(*(_secondary.update_agent)) {}

 protected:
  class MetadataInvalidator : public Metadata {
   public:
    MetadataInvalidator(const Uptane::RawMetaPack& valid_metadata, const Uptane::RepositoryType& repo,
                        const Uptane::Role& role)
        : Metadata(valid_metadata), _repo_type(repo), _role(role) {}

    bool getRoleMetadata(std::string* result, const Uptane::RepositoryType& repo, const Uptane::Role& role,
                         Uptane::Version version) const override {
      auto return_val = Metadata::getRoleMetadata(result, repo, role, version);
      if (!(_repo_type == repo && _role == role)) {
        return return_val;
      }
      (*result)[10] = 'f';
      return true;
    }

   private:
    Uptane::RepositoryType _repo_type;
    Uptane::Role _role;
  };

  MetadataInvalidator currentMetadata() const {
    return MetadataInvalidator(_uptane_repo.getCurrentMetadata(), GetParam().first, GetParam().second);
  }

  AktualizrSecondaryWrapper _secondary;
  UptaneRepoWrapper _uptane_repo;
  NiceMock<UpdateAgentMock>& _update_agent;
};

/**
 * Parameterized test,
 * The parameter is std::pair<Uptane::RepositoryType, Uptane::Role> to indicate which metadata to malform
 *
 * see INSTANTIATE_TEST_SUITE_P for the test instantiations with concrete parameter values
 */
// TEST_P(SecondaryTestNegative, MalformedMetadaJson) {
//  EXPECT_FALSE(_secondary->putMetadata(currentMetadata()));

//  EXPECT_CALL(_update_agent, download).Times(0);
//  EXPECT_CALL(_update_agent, install).Times(0);

//  EXPECT_FALSE(_secondary->sendFirmware("firmware"));

//  EXPECT_NE(_secondary->install("target"), data::ResultCode::Numeric::kOk);
//}

/**
 * Instantiates the parameterized test for each specified value of std::pair<Uptane::RepositoryType, Uptane::Role>
 * the parameter value indicates which metadata to malform
 */
INSTANTIATE_TEST_SUITE_P(SecondaryTestMalformedMetadata, SecondaryTestNegative,
                         ::testing::Values(std::make_pair(Uptane::RepositoryType::Director(), Uptane::Role::Root()),
                                           std::make_pair(Uptane::RepositoryType::Director(), Uptane::Role::Targets()),
                                           std::make_pair(Uptane::RepositoryType::Image(), Uptane::Role::Root()),
                                           std::make_pair(Uptane::RepositoryType::Image(), Uptane::Role::Timestamp()),
                                           std::make_pair(Uptane::RepositoryType::Image(), Uptane::Role::Snapshot()),
                                           std::make_pair(Uptane::RepositoryType::Image(), Uptane::Role::Targets())));

TEST_F(SecondaryTest, fullUptaneVerificationPositive) {
  EXPECT_CALL(_update_agent, receiveData)
      .Times(target_size / send_buffer_size + (target_size % send_buffer_size ? 1 : 0));
  EXPECT_CALL(_update_agent, install).Times(1);

  ASSERT_TRUE(_secondary->putMetadata(_uptane_repo.getCurrentMetadata()));
  ASSERT_EQ(sendImageFile(), data::ResultCode::Numeric::kOk);
  ASSERT_EQ(_secondary->install(), data::ResultCode::Numeric::kOk);

  // check if a file was actually updated
  ASSERT_TRUE(boost::filesystem::exists(_secondary.targetFilepath()));
  auto target = getDefaultTarget();

  // check the updated file hash
  auto target_hash = Uptane::Hash(Uptane::Hash::Type::kSha256, target.sha256Hash());
  auto target_file_hash =
      Uptane::Hash::generate(Uptane::Hash::Type::kSha256, Utils::readFile(_secondary.targetFilepath()));
  EXPECT_EQ(target_hash, target_file_hash);

  // check the secondary manifest
  auto manifest = _secondary->getManifest();
  EXPECT_EQ(manifest.installedImageHash(), target_file_hash);
  EXPECT_EQ(manifest.filepath(), target.filename());
}

TEST_F(SecondaryTest, TwoImagesAndOneTarget) {
  // two images for the same ECU, just one of them is added as a target and signed
  // default image and corresponding target has been already added, just add another image
  _uptane_repo.addImageFile("second_image_00", _secondary->hwID().ToString(), _secondary->serial().ToString(),
                            target_size, false, false);
  EXPECT_TRUE(_secondary->putMetadata(_uptane_repo.getCurrentMetadata()));
}

TEST_F(SecondaryTest, IncorrectTargetQuantity) {
  {
    // two targets for the same ECU
    _uptane_repo.addImageFile("second_target", _secondary->hwID().ToString(), _secondary->serial().ToString());

    auto meta = _uptane_repo.getCurrentMetadata();
    EXPECT_FALSE(_secondary->putMetadata(meta));
  }

  {
    // zero targets for the ECU being tested
    auto metadata = UptaneRepoWrapper().addImageFile("mytarget", _secondary->hwID().ToString(), "non-existing-serial");

    EXPECT_FALSE(_secondary->putMetadata(metadata));
  }

  {
    // zero targets for the ECU being tested
    auto metadata = UptaneRepoWrapper().addImageFile("mytarget", "non-existig-hwid", _secondary->serial().ToString());

    EXPECT_FALSE(_secondary->putMetadata(metadata));
  }
}

TEST_F(SecondaryTest, DirectorRootVersionIncremented) {
  _uptane_repo.refreshRoot(Uptane::RepositoryType::Director());
  EXPECT_TRUE(_secondary->putMetadata(_uptane_repo.getCurrentMetadata()));
}

TEST_F(SecondaryTest, ImageRootVersionIncremented) {
  _uptane_repo.refreshRoot(Uptane::RepositoryType::Image());
  EXPECT_TRUE(_secondary->putMetadata(_uptane_repo.getCurrentMetadata()));
}

TEST_F(SecondaryTest, SmallerImageFileSize) {
  EXPECT_CALL(_update_agent, receiveData)
      .Times((target_size - inavlid_target_size_delta) / send_buffer_size +
             ((target_size - inavlid_target_size_delta) % send_buffer_size ? 1 : 0));
  EXPECT_CALL(_update_agent, install).Times(1);

  EXPECT_TRUE(_secondary->putMetadata(_uptane_repo.getCurrentMetadata()));

  EXPECT_EQ(sendImageFile(_smaller_target), data::ResultCode::Numeric::kOk);
  EXPECT_NE(_secondary->install(), data::ResultCode::Numeric::kOk);
}

TEST_F(SecondaryTest, BiggerImageFileSize) {
  EXPECT_CALL(_update_agent, receiveData)
      .Times((target_size + inavlid_target_size_delta) / send_buffer_size +
             ((target_size + inavlid_target_size_delta) % send_buffer_size ? 1 : 0));
  EXPECT_CALL(_update_agent, install).Times(1);

  EXPECT_TRUE(_secondary->putMetadata(_uptane_repo.getCurrentMetadata()));

  EXPECT_EQ(sendImageFile(_bigger_target), data::ResultCode::Numeric::kOk);
  EXPECT_NE(_secondary->install(), data::ResultCode::Numeric::kOk);
}

TEST_F(SecondaryTest, InvalidImageData) {
  EXPECT_CALL(_update_agent, receiveData)
      .Times(target_size / send_buffer_size + (target_size % send_buffer_size ? 1 : 0));
  EXPECT_CALL(_update_agent, install).Times(1);

  EXPECT_TRUE(_secondary->putMetadata(_uptane_repo.getCurrentMetadata()));
  EXPECT_EQ(sendImageFile(_broken_target), data::ResultCode::Numeric::kOk);
  EXPECT_NE(_secondary->install(), data::ResultCode::Numeric::kOk);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);

  logger_init();
  logger_set_threshold(boost::log::trivial::info);

  return RUN_ALL_TESTS();
}
