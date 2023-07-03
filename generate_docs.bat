REM 设置源代码目录和文档输出目录
SET SOURCE_DIR=src\main\java
SET DOC_DIR=doc/javadoc

REM 使用 javadoc 生成文档
javadoc -d "%DOC_DIR%" -sourcepath "%SOURCE_DIR%" com.af.device.impl

REM 构建项目的其他步骤...
