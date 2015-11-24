----------


###持续集成相关

hudson
subversion
http://www.cnblogs.com/SXLBlog/archive/2011/06/14/2080270.html


###编译部署全流程

步骤如下：

1. 首先将从scm拉取到的对应的代码进行打包(build_source_code)，打包过程主要是对于一些细节的处理，指定好路径，不进行打包的文件(参考deploy.sh)
2. 针对打包的文件，独立出一个test目录，进行 静态代码检测/线下地址检测/xss检测(参见build.sh 文件)
3. 将各个模块的编译信息写入build_info文件
4. 进行环境部署，通过解析build_info，deploy这套，将对应的tar包解析移动到正确的位置deploy
5. 进行地址替换操作


