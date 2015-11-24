#!/bin/bash
##### 脚本内部变量均__开头

__PWD=$(pwd)


# 默认的排除文件列表
__DEFAULT_EXCLUDE_FILE=${__PWD}/_build/.defaultExclude
__PROTOBUF_SCRIPT=${__PWD}/_build/protobuf.sh 
# 执行自动化测试的时候，变换目录
if [ "$1" = "-t" ];then
		__DEFAULT_EXCLUDE_FILE=${__PWD}/../.defaultExclude
		__PROTOBUF_SCRIPT=${__PWD}/../protobuf.sh
fi


# 自定义需要排除的文件列表 tar --exclude-from 支持的格式，文件为'.exclude'
__EXCLUDE_FILE=${__PWD}/.exclude


# 常量
__OUTPUT_DIR=${__PWD}/'output'
__DEPLOY_OFFLINE=$__OUTPUT_DIR/'deploy.offline'
__DEFAULT_DEPLOY_OFFLINE_PATH='/home/work/orp'


#清理环境
rm -rf $__OUTPUT_DIR 
mkdir -p $__OUTPUT_DIR

# 变量初始化
# 取默认的模块名称作为tar包名
if [  ${#__PRODUCTS[@]} -eq 0 ];then
	echo -e "### __PRODUCTS 未指定，需要强制指定 ### \r\n"
	exit 1
fi
__PRODUCTS_NUM=${#__PRODUCTS[@]}

if [  ${#__TAR_TARGETS[@]} -eq 0 ];then
	__TAR_TARGETS=('./')
fi
__TAR_TARGETS_NUM=${#__TAR_TARGETS[@]}

if [  ${#__OFFLINE_PATH[@]} -eq 0 ];then
	for ((i =0 ; i <= $__PRODUCTS_NUM -1; i++));do
		__OFFLINE_PATH[$i]=$__DEFAULT_DEPLOY_OFFLINE_PATH
	done

fi
__OFFLINE_PATH_NUM=${#__OFFLINE_PATH[@]}

# 主体逻辑，支持多个模块打包
if [ $__PRODUCTS_NUM -ne $__TAR_TARGETS_NUM ];then
	echo "__PRODUCTS=$__PRODUCTS_NUM 和 __TAR_TARGETS=$__TAR_TARGETS_NUM 数量不匹配 "
	exit 1
else
	if [ $__OFFLINE_PATH_NUM -gt 0 ] && [ $__PRODUCTS_NUM -ne $__OFFLINE_PATH_NUM ] ;then
		echo "__PRODUCTS=$__TAR_TARGETS_NUM 和 __OFFLINE_PATH=$__OFFLINE_PATH_NUM 数量不匹配"
		exit 1
	fi
fi


# 线下部署地址文件生成1
if [ $__OFFLINE_PATH_NUM -gt 0 ];then
	echo "[deployinfo]" >> $__DEPLOY_OFFLINE
fi

__PRODUCTS_PATH=()
for ((i = 0; i <= $__PRODUCTS_NUM -1; i++)); do
	echo -e "\r\n### ${__PRODUCTS[i]} 模块打包开始 ###"
	__PRODUCTS_PATH[$i]=$__OUTPUT_DIR/${__PRODUCTS[i]}'.tar.gz'

	# 切换到tar命令的源地址根目录
	if [ "x$__TAR_SOURCE_ROOT_DIR" != "x" ];then			
		cd $__TAR_SOURCE_ROOT_DIR
	fi

	if [ -f $__EXCLUDE_FILE ] ;then
		tar -zcvf ${__PRODUCTS_PATH[i]} --exclude-from=$__DEFAULT_EXCLUDE_FILE --exclude-from=$__EXCLUDE_FILE ${__TAR_TARGETS[i]}

	else
		tar -zcvf ${__PRODUCTS_PATH[i]} --exclude-from=$__DEFAULT_EXCLUDE_FILE ${__TAR_TARGETS[i]}
	fi

	# 回到执行脚本根目录
	if [ "x$__TAR_SOURCE_ROOT_DIR" != "x" ];then			
		cd -
	fi

	md5sum ${__PRODUCTS_PATH} > $__OUTPUT_DIR/${__PRODUCTS[i]}'.tar.gz.md5'

	# 线下部署地址文件生成
	if [ ${#__OFFLINE_PATH} -gt 0 ];then
		echo "${__PRODUCTS[i]}.tar.gz=${__OFFLINE_PATH[i]}" >> $__DEPLOY_OFFLINE
	fi
	echo -e "### ${__PRODUCTS[i]} 模块打包结束 ###\r\n"
done


# 处理tar包
__TEST_DIR='.tempTest'
rm -rf $__TEST_DIR # 避免临时目录冲突，删除老的目录
mkdir -p $__TEST_DIR

for ((i = 0; i <= $__PRODUCTS_NUM -1; i++)); do
	tar xzvf ${__PRODUCTS_PATH[i]} -C $__TEST_DIR  1>/dev/null
done


rm -rf $__TEST_DIR
echo -e "编译结束"