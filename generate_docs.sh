#!/bin/bash

# 定义源代码目录和文档输出目录
SOURCE_DIR="src/main/java"
DOC_DIR="doc"

# 使用 javadoc 生成文档
javadoc -d "$DOC_DIR" -sourcepath "$SOURCE_DIR" com.af.device.impl

# 构建项目的其他步骤...
