cmake_minimum_required(VERSION 3.8)

project(WinFwIPBlocker)

aux_source_directory(. SRC_LIST)
add_executable(${PROJECT_NAME} ${SRC_LIST})

configure_file("ip_black_list.txt" "ip_black_list.txt" COPYONLY)