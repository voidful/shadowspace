#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "pathname"
require "xcodeproj"

ROOT = File.expand_path("..", __dir__)
PROJECT_DIR = File.join(ROOT, "AppStore")
PROJECT_PATH = File.join(PROJECT_DIR, "ShadowSpace.xcodeproj")
DEPLOYMENT_TARGET = "14.0"
APP_BUNDLE_ID = "com.voidful.shadowspace"
EXTENSION_BUNDLE_ID = "com.voidful.shadowspace.ShadowTunnel"
RELEASE_VERSION = File.read(File.join(ROOT, "VERSION")).strip
BUILD_NUMBER = File.read(File.join(ROOT, "BUILD_NUMBER")).strip

def repo_path(path)
  File.join(ROOT, path)
end

def relative(path)
  path.sub("#{ROOT}/", "")
end

def project_relative(path)
  Pathname.new(repo_path(path)).relative_path_from(Pathname.new(PROJECT_DIR)).to_s
end

def source_files(globs, excludes: [])
  excluded = excludes.map { |path| repo_path(path) }
  globs.flat_map { |glob| Dir[repo_path(glob)] }
       .select { |path| File.file?(path) && File.extname(path) == ".swift" }
       .reject { |path| excluded.include?(path) }
       .sort
       .map { |path| relative(path) }
end

def add_file(project, path)
  project_path = project_relative(path)
  project.main_group.find_file_by_path(project_path) || project.main_group.new_file(project_path)
end

def add_sources(project, target, paths)
  refs = paths.map { |path| add_file(project, path) }
  target.add_file_references(refs)
end

def add_resources(project, target, paths)
  refs = paths.map { |path| add_file(project, path) }
  target.add_resources(refs)
end

def set_common_build_settings(target)
  target.build_configurations.each do |config|
    settings = config.build_settings
    settings["MACOSX_DEPLOYMENT_TARGET"] = DEPLOYMENT_TARGET
    settings["SWIFT_VERSION"] = "5.0"
    settings["CODE_SIGN_STYLE"] = "Automatic"
    settings["CLANG_ENABLE_MODULES"] = "YES"
    settings["ENABLE_HARDENED_RUNTIME"] = "YES"
  end
end

def embed_product(target, product_reference, phase_name, destination)
  phase = target.copy_files_build_phases.find { |p| p.name == phase_name } ||
          target.new_copy_files_build_phase(phase_name)
  phase.symbol_dst_subfolder_spec = destination
  build_file = phase.add_file_reference(product_reference)
  build_file.settings = { "ATTRIBUTES" => ["CodeSignOnCopy", "RemoveHeadersOnCopy"] }
  build_file
end

FileUtils.rm_rf(PROJECT_PATH)
project = Xcodeproj::Project.new(PROJECT_PATH)
project.root_object.attributes["LastSwiftUpdateCheck"] = "2650"
project.root_object.attributes["LastUpgradeCheck"] = "2650"

core_target = project.new_target(:framework, "ShadowCore", :osx, DEPLOYMENT_TARGET)
kit_target = project.new_target(:framework, "ShadowSpaceKit", :osx, DEPLOYMENT_TARGET)
extension_target = project.new_target(:app_extension, "ShadowTunnel", :osx, DEPLOYMENT_TARGET)
app_target = project.new_target(:application, "ShadowSpace", :osx, DEPLOYMENT_TARGET)

[core_target, kit_target, extension_target, app_target].each { |target| set_common_build_settings(target) }

core_target.build_configurations.each do |config|
  config.build_settings["PRODUCT_BUNDLE_IDENTIFIER"] = "#{APP_BUNDLE_ID}.ShadowCore"
  config.build_settings["DEFINES_MODULE"] = "YES"
  config.build_settings["GENERATE_INFOPLIST_FILE"] = "YES"
  config.build_settings["MARKETING_VERSION"] = RELEASE_VERSION
  config.build_settings["CURRENT_PROJECT_VERSION"] = BUILD_NUMBER
  config.build_settings["INSTALL_PATH"] = "@rpath"
  config.build_settings["SKIP_INSTALL"] = "YES"
end

kit_target.build_configurations.each do |config|
  config.build_settings["PRODUCT_BUNDLE_IDENTIFIER"] = "#{APP_BUNDLE_ID}.ShadowSpaceKit"
  config.build_settings["DEFINES_MODULE"] = "YES"
  config.build_settings["GENERATE_INFOPLIST_FILE"] = "YES"
  config.build_settings["MARKETING_VERSION"] = RELEASE_VERSION
  config.build_settings["CURRENT_PROJECT_VERSION"] = BUILD_NUMBER
  config.build_settings["INSTALL_PATH"] = "@rpath"
  config.build_settings["SKIP_INSTALL"] = "YES"
  config.build_settings["OTHER_SWIFT_FLAGS"] = "$(inherited) -D APP_STORE -D SHADOWSPACE_APP"
  config.build_settings["LD_RUNPATH_SEARCH_PATHS"] = "$(inherited) @loader_path/Frameworks @loader_path/../Frameworks"
end

extension_target.build_configurations.each do |config|
  config.build_settings["PRODUCT_BUNDLE_IDENTIFIER"] = EXTENSION_BUNDLE_ID
  config.build_settings["MARKETING_VERSION"] = RELEASE_VERSION
  config.build_settings["CURRENT_PROJECT_VERSION"] = BUILD_NUMBER
  config.build_settings["INFOPLIST_FILE"] = "ShadowTunnel/Info.plist"
  config.build_settings["CODE_SIGN_ENTITLEMENTS"] = "entitlements/ShadowTunnel.entitlements"
  config.build_settings["APPLICATION_EXTENSION_API_ONLY"] = "YES"
  config.build_settings["SKIP_INSTALL"] = "YES"
  config.build_settings["OTHER_SWIFT_FLAGS"] = "$(inherited) -D APP_STORE -D SHADOWSPACE_EXTENSION"
  config.build_settings["LD_RUNPATH_SEARCH_PATHS"] = "$(inherited) @executable_path/../Frameworks @executable_path/../../../../Frameworks"
end

app_target.build_configurations.each do |config|
  config.build_settings["PRODUCT_BUNDLE_IDENTIFIER"] = APP_BUNDLE_ID
  config.build_settings["MARKETING_VERSION"] = RELEASE_VERSION
  config.build_settings["CURRENT_PROJECT_VERSION"] = BUILD_NUMBER
  config.build_settings["INFOPLIST_FILE"] = "ShadowSpace-Info.plist"
  config.build_settings["CODE_SIGN_ENTITLEMENTS"] = "entitlements/ShadowSpace.appstore.entitlements"
  config.build_settings["OTHER_SWIFT_FLAGS"] = "$(inherited) -D APP_STORE"
  config.build_settings["LD_RUNPATH_SEARCH_PATHS"] = "$(inherited) @executable_path/../Frameworks"
  config.build_settings["ASSETCATALOG_COMPILER_APPICON_NAME"] = ""
end

add_sources(project, core_target, source_files(["Sources/ShadowCore/**/*.swift"]))

kit_sources = source_files(
  ["Sources/ShadowSpaceKit/**/*.swift"],
  excludes: [
    "Sources/ShadowSpaceKit/Core/ClashAPIClient.swift",
    "Sources/ShadowSpaceKit/Core/EngineManager.swift",
    "Sources/ShadowSpaceKit/Core/SingBoxConfigBuilder.swift",
    "Sources/ShadowSpaceKit/Core/SystemProxyManager.swift"
  ]
)
kit_sources += [
  "AppStore/TunnelManager.swift",
  "AppStore/ShadowTunnel/SharedConfig.swift"
]
add_sources(project, kit_target, kit_sources)

add_sources(project, extension_target, [
  "AppStore/ShadowTunnel/ShadowTunnelProvider.swift",
  "AppStore/ShadowTunnel/SharedConfig.swift"
])

add_sources(project, app_target, ["Sources/ShadowSpace/main.swift"])
add_resources(project, app_target, [
  "Resources/AppIcon.icns",
  "AppStore/PrivacyInfo.xcprivacy"
])

kit_target.add_dependency(core_target)
kit_target.frameworks_build_phase.add_file_reference(core_target.product_reference)

extension_target.add_dependency(core_target)
extension_target.frameworks_build_phase.add_file_reference(core_target.product_reference)
embed_product(extension_target, core_target.product_reference, "Embed Frameworks", :frameworks)

app_target.add_dependency(kit_target)
app_target.add_dependency(core_target)
app_target.add_dependency(extension_target)
app_target.frameworks_build_phase.add_file_reference(kit_target.product_reference)
embed_product(app_target, kit_target.product_reference, "Embed Frameworks", :frameworks)
embed_product(app_target, core_target.product_reference, "Embed Frameworks", :frameworks)
embed_product(app_target, extension_target.product_reference, "Embed App Extensions", :plug_ins)

scheme = Xcodeproj::XCScheme.new
scheme.add_build_target(app_target)
scheme.add_build_target(extension_target)
scheme.set_launch_target(app_target)
scheme.save_as(PROJECT_PATH, "ShadowSpace", true)

project.save
puts "Generated #{relative(PROJECT_PATH)}"
