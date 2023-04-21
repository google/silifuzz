workspace(name = "silifuzz")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository", "new_git_repository")

###############################################################################
# Bazel Skylib (transitively required by com_google_absl).
###############################################################################

http_archive(
    name = "bazel_skylib",
    sha256 = "f24ab666394232f834f74d19e2ff142b0af17466ea0c69a3f4c276ee75f6efce",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.4.0/bazel-skylib-1.4.0.tar.gz",
        "https://github.com/bazelbuild/bazel-skylib/releases/download/1.4.0/bazel-skylib-1.4.0.tar.gz",
    ],
)

load("@bazel_skylib//:workspace.bzl", "bazel_skylib_workspace")

bazel_skylib_workspace()

###############################################################################
# C++ build rules
# Configure the bootstrapped Clang and LLVM toolchain for Bazel.
###############################################################################

http_archive(
    name = "rules_cc",
    sha256 = "2004c71f3e0a88080b2bd3b6d3b73b4c597116db9c9a36676d0ffad39b849214",
    strip_prefix = "rules_cc-0.0.5",
    urls = ["https://github.com/bazelbuild/rules_cc/releases/download/0.0.5/rules_cc-0.0.5.tar.gz"],
)

###############################################################################
# Abseil
###############################################################################

abseil_ref = "refs/tags"

abseil_ver = "20230125.0"

# Use these values to get the tip of the master branch:
# abseil_ref = "refs/heads"
# abseil_ver = "master"

http_archive(
    name = "com_google_absl",
    sha256 = "3ea49a7d97421b88a8c48a0de16c16048e17725c7ec0f1d3ea2683a2a75adc21",
    strip_prefix = "abseil-cpp-%s" % abseil_ver,
    url = "https://github.com/abseil/abseil-cpp/archive/%s/%s.tar.gz" % (abseil_ref, abseil_ver),
)

###############################################################################
# GoogleTest/GoogleMock
###############################################################################

http_archive(
    name = "com_google_googletest",
    sha256 = "ad7fdba11ea011c1d925b3289cf4af2c66a352e18d4c7264392fead75e919363",
    strip_prefix = "googletest-1.13.0",
    url = "https://github.com/google/googletest/archive/refs/tags/v1.13.0.tar.gz",
)

###############################################################################
# Protobufs
###############################################################################
# proto_library, cc_proto_library, and java_proto_library rules implicitly
# depend on @com_google_protobuf for protoc and proto runtimes.
# This statement defines the @com_google_protobuf repo.
http_archive(
    name = "com_google_protobuf",
    sha256 = "930c2c3b5ecc6c9c12615cf5ad93f1cd6e12d0aba862b572e076259970ac3a53",
    strip_prefix = "protobuf-3.21.12",
    urls = ["https://github.com/protocolbuffers/protobuf/archive/v3.21.12.tar.gz"],
)

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()

###############################################################################
# Minor third_party dependencies
###############################################################################

lss_ver = "32a80cda3c885e0db9bcd4c67d1c4b479057d943"

new_git_repository(
    name = "lss",
    build_file = "@silifuzz//:third_party/BUILD.lss",
    commit = lss_ver,
    remote = "https://chromium.googlesource.com/linux-syscall-support",
    shallow_since = "1657142711 +0000",
)

new_git_repository(
    name = "cityhash",
    build_file = "@silifuzz//:third_party/BUILD.cityhash",
    commit = "8af9b8c2b889d80c22d6bc26ba0df1afb79a30db",
    patch_cmds = [
        # Running "configure" creates the config.h file needed for this library.
        "./configure",
        "mv config.h src",
        """sed -i -e 's/<city.h>/"city.h"/' src/*.cc src/*.h""",
        """sed -i -e 's/<citycrc.h>/"citycrc.h"/' src/*.cc""",
    ],
    remote = "https://github.com/google/cityhash",
    shallow_since = "1375313681 +0000",
)

new_git_repository(
    name = "mbuild",
    build_file = "@silifuzz//:third_party/BUILD.mbuild",
    commit = "1cb4f44e9b249626392a275e6f59c00ea16a47ed",
    patch_cmds = [
        "rm -f setup.py",
        "mv mbuild/*.py .",
    ],
    remote = "https://github.com/intelxed/mbuild",
    shallow_since = "1573652175 -0500",
)

new_git_repository(
    name = "libxed",
    build_file = "@silifuzz//:third_party/BUILD.libxed",
    commit = "801b876fe6a6d321b1f4027b6bb4adaee7ecd0a7",
    patch_cmds = [
        "sed -i -e 's|xed/xed-interface.h|xed-interface.h|' examples/xed-tester.c",
    ],
    remote = "https://github.com/intelxed/xed",
    shallow_since = "1522099305 -0400",
)

git_repository(
    name = "centipede",
    branch = "main",
    remote = "https://github.com/google/centipede",
)

http_archive(
    name = "liblzma",
    build_file = "@silifuzz//:third_party/BUILD.liblzma",
    sha256 = "f6f4910fd033078738bd82bfba4f49219d03b17eb0794eb91efbae419f4aba10",
    strip_prefix = "xz-5.2.5",
    urls = [
        "https://storage.googleapis.com/tensorstore-bazel-mirror/tukaani.org/xz/xz-5.2.5.tar.gz",
        "https://tukaani.org/xz/xz-5.2.5.tar.gz",
    ],
)

# Google benchmark. Official release 1.7.0
http_archive(
    name = "com_github_google_benchmark",
    sha256 = "3aff99169fa8bdee356eaa1f691e835a6e57b1efeadb8a0f9f228531158246ac",
    strip_prefix = "benchmark-1.7.0",
    urls = ["https://github.com/google/benchmark/archive/refs/tags/v1.7.0.tar.gz"],
)

# Capstone disassembler
new_git_repository(
    name = "capstone",
    build_file = "@silifuzz//:third_party/BUILD.capstone",
    commit = "702dbe78ca116de8ec65f122d9202c2c1f4a2b4c",
    remote = "https://github.com/capstone-engine/capstone.git",
)

# Unicorn for the proxies
new_git_repository(
    name = "unicorn",
    build_file = "@silifuzz//:third_party/BUILD.unicorn",
    commit = "63a445cbba18bf1313ac3699b5d25462b5d529f4",
    patch_cmds = [
        "sed -i -e 's|ARM64_REGS_STORAGE_SIZE|DEFAULT_VISIBILITY ARM64_REGS_STORAGE_SIZE|' qemu/target-arm/unicorn.h",
        "sed -i -e 's|X86_REGS_STORAGE_SIZE|DEFAULT_VISIBILITY X86_REGS_STORAGE_SIZE|' qemu/target-i386/unicorn.h",
    ],
    remote = "https://github.com/unicorn-engine/unicorn",
    shallow_since = "1639356032 +0800",
)

http_archive(
    name = "absl_py",
    sha256 = "b9130d6f49a21dc44f56da89d5e8409807e93d28c194c23e27777f3c8cceef81",
    strip_prefix = "abseil-py-1.2.0",
    urls = ["https://github.com/abseil/abseil-py/archive/refs/tags/v1.2.0.tar.gz"],
)

# To use the latest version of FuzzTest, update this regularly to the latest
# commit in the main branch: https://github.com/google/fuzztest/commits/main
FUZZTEST_COMMIT = "62cf00c7341eb05d128d0a3cbce79ac31dbda032"

http_archive(
    name = "com_google_fuzztest",
    strip_prefix = "fuzztest-" + FUZZTEST_COMMIT,
    url = "https://github.com/google/fuzztest/archive/" + FUZZTEST_COMMIT + ".zip",
)

# Required by com_google_fuzztest.
http_archive(
    name = "com_googlesource_code_re2",
    sha256 = "f89c61410a072e5cbcf8c27e3a778da7d6fd2f2b5b1445cd4f4508bee946ab0f",
    strip_prefix = "re2-2022-06-01",
    url = "https://github.com/google/re2/archive/refs/tags/2022-06-01.tar.gz",
)
