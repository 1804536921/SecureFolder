cmake_minimum_required(VERSION 3.15)
project(SecureFolder VERSION 1.0.0 LANGUAGES CXX)

# C++17 标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows特定设置
if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DUNICODE)
    add_definitions(-D_UNICODE)
    add_definitions(-D_WIN32_WINNT=0x0601)  # Windows 7+

    link_libraries(bcrypt)
    link_libraries(user32)
    link_libraries(advapi32)
    link_libraries(shell32)
    link_libraries(shlwapi)
    link_libraries(crypt32)
    link_libraries(comctl32)
    link_libraries(ole32)
endif()

# ==================== 主程序（命令行 + GUI） ====================

set(MAIN_SOURCES
    src/main.cpp
    src/Core/CryptoEngine.cpp
    src/Core/FolderDisguise.cpp
    src/Core/SecureDelete.cpp
    src/Core/SecureFolderManager.cpp
    src/UI/GUIDialog.cpp
    resources/resource.rc
)

set(MAIN_HEADERS
    src/Common/Types.h
    src/Common/Utils.h
    src/Core/CryptoEngine.h
    src/Core/FolderDisguise.h
    src/Core/SecureDelete.h
    src/Core/SecureFolderManager.h
    src/UI/GUIDialog.h
)

add_executable(SecureFolder ${MAIN_SOURCES} ${MAIN_HEADERS})

target_include_directories(SecureFolder PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/Common
    ${CMAKE_SOURCE_DIR}/src/Core
    ${CMAKE_SOURCE_DIR}/src/UI
    ${CMAKE_SOURCE_DIR}/resources
)

if(MSVC)
    target_compile_options(SecureFolder PRIVATE /W4 /O2 /EHsc /utf-8)
    target_compile_definitions(SecureFolder PRIVATE NDEBUG)
    target_link_options(SecureFolder PRIVATE /SUBSYSTEM:WINDOWS)
endif()

# ==================== Shell扩展DLL ====================

set(SHELL_EXT_SOURCES
    src/ShellExt/ShellExtension.cpp
    src/Core/CryptoEngine.cpp
    src/Core/FolderDisguise.cpp
    src/Core/SecureDelete.cpp
    src/Core/SecureFolderManager.cpp
    src/UI/GUIDialog.cpp
    resources/shell_resource.rc
)

set(SHELL_EXT_HEADERS
    src/Common/Types.h
    src/Common/Utils.h
    src/Core/CryptoEngine.h
    src/Core/FolderDisguise.h
    src/Core/SecureDelete.h
    src/Core/SecureFolderManager.h
    src/UI/GUIDialog.h
)

add_library(SecureFolderShellExt SHARED ${SHELL_EXT_SOURCES} ${SHELL_EXT_HEADERS})

target_include_directories(SecureFolderShellExt PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/Common
    ${CMAKE_SOURCE_DIR}/src/Core
    ${CMAKE_SOURCE_DIR}/src/UI
    ${CMAKE_SOURCE_DIR}/src/ShellExt
    ${CMAKE_SOURCE_DIR}/resources
)

if(MSVC)
    target_compile_options(SecureFolderShellExt PRIVATE /W4 /O2 /EHsc /utf-8)
    target_compile_definitions(SecureFolderShellExt PRIVATE NDEBUG)

    # DLL需要特殊链接选项
    target_link_options(SecureFolderShellExt PRIVATE
        /SUBSYSTEM:WINDOWS
        /DEF:${CMAKE_SOURCE_DIR}/src/ShellExt/ShellExt.def
    )
endif()

# ==================== 安装配置 ====================

install(TARGETS SecureFolder DESTINATION bin)
install(TARGETS SecureFolderShellExt DESTINATION bin)

# ==================== 打印信息 ====================

message(STATUS "")
message(STATUS "SecureFolder 构建配置:")
message(STATUS "  版本: ${PROJECT_VERSION}")
message(STATUS "  C++ 标准: ${CMAKE_CXX_STANDARD}")
message(STATUS "  编译器: ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "  目标:")
message(STATUS "    - SecureFolder.exe (主程序)")
message(STATUS "    - SecureFolderShellExt.dll (右键菜单扩展)")
message(STATUS "")