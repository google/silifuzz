load("//tools/build_defs/license:license.bzl", "license")

package(
    default_applicable_licenses = ["//third_party/silifuzz_libunwind:license"],
    default_visibility = ["//visibility:public"],
)

license(
    name = "license",
    package_name = "silifuzz_libunwind",
)

licenses(["notice"])

# Export all files.
exports_files(["LICENSE"] + glob([
    "*.S",
    "*.inc",
]))
