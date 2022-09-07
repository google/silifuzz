workspace(name = "silifuzz")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository", "new_git_repository")

###############################################################################
# Bazel Skylib (transitively required by com_google_absl).
###############################################################################

skylib_ver = "1.2.1"

http_archive(
    name = "bazel_skylib",
    sha256 = "f7be3474d42aae265405a592bb7da8e171919d74c16f082a5457840f06054728",
    url = "https://github.com/bazelbuild/bazel-skylib/releases/download/%s/bazel-skylib-%s.tar.gz" % (skylib_ver, skylib_ver),
)

###############################################################################
# C++ build rules
# Configure the bootstrapped Clang and LLVM toolchain for Bazel.
###############################################################################

rules_cc_ver = "262ebec3c2296296526740db4aefce68c80de7fa"

http_archive(
    name = "rules_cc",
    sha256 = "9a446e9dd9c1bb180c86977a8dc1e9e659550ae732ae58bd2e8fd51e15b2c91d",
    strip_prefix = "rules_cc-%s" % rules_cc_ver,
    url = "https://github.com/bazelbuild/rules_cc/archive/%s.zip" % rules_cc_ver,
)

###############################################################################
# Abseil
###############################################################################

#abseil_ref = "tags"
#abseil_ver = "20220623.0"

# Use these values to get the tip of the master branch:
# abseil_ref = "heads"
# abseil_ver = "master"
abseil_ver = "92fdbfb301f8b301b28ab5c99e7361e775c2fb8a"

http_archive(
    name = "com_google_absl",
    sha256 = "71d38c5f44997a5ccbc338f904c8682b40c25cad60b9cbaf27087a917228d5fa",
    strip_prefix = "abseil-cpp-%s" % abseil_ver,
    # TODO(ksteuck): Switch back to fetching a tag once there's one with logging.
    #url = "https://github.com/abseil/abseil-cpp/archive/refs/%s/%s.tar.gz" % (abseil_ref, abseil_ver),
    url = "https://github.com/abseil/abseil-cpp/archive/%s.tar.gz" % abseil_ver,
)

###############################################################################
# GoogleTest/GoogleMock
###############################################################################

# Version as of 2021-12-07.
googletest_ver = "4c5650f68866e3c2e60361d5c4c95c6f335fb64b"

http_archive(
    name = "com_google_googletest",
    sha256 = "770e61fa13d51320736c2881ff6279212e4eab8a9100709fff8c44759f61d126",
    strip_prefix = "googletest-%s" % googletest_ver,
    url = "https://github.com/google/googletest/archive/%s.tar.gz" % googletest_ver,
)

###############################################################################
# Protobufs
###############################################################################
# proto_library, cc_proto_library, and java_proto_library rules implicitly
# depend on @com_google_protobuf for protoc and proto runtimes.
# This statement defines the @com_google_protobuf repo.
http_archive(
    name = "com_google_protobuf",
    sha256 = "85d42d4485f36f8cec3e475a3b9e841d7d78523cd775de3a86dba77081f4ca25",
    strip_prefix = "protobuf-3.21.4",
    urls = ["https://github.com/protocolbuffers/protobuf/archive/v3.21.4.tar.gz"],
)

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()

###############################################################################
# Minor third_party dependencies
###############################################################################

lss_ver = "32a80cda3c885e0db9bcd4c67d1c4b479057d943"

new_git_repository(
    name = "lss",
    build_file = "@//:third_party/BUILD.lss",
    commit = lss_ver,
    remote = "https://chromium.googlesource.com/linux-syscall-support",
    shallow_since = "1657142711 +0000",
)

new_git_repository(
    name = "cityhash",
    build_file = "@//:third_party/BUILD.cityhash",
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
    build_file = "@//:third_party/BUILD.mbuild",
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
    build_file = "@//:third_party/BUILD.libxed",
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
    build_file = "//:third_party/BUILD.liblzma",
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

# Unicorn for the proxies
new_git_repository(
    name = "unicorn",
    build_file = "@//:third_party/BUILD.unicorn",
    commit = "63a445cbba18bf1313ac3699b5d25462b5d529f4",
    remote = "https://github.com/unicorn-engine/unicorn",
    patch_cmds = [
        "sed -i -e 's|ARM64_REGS_STORAGE_SIZE|DEFAULT_VISIBILITY ARM64_REGS_STORAGE_SIZE|' qemu/target-arm/unicorn.h",
    ],
    shallow_since = "1639356032 +0800",
)
