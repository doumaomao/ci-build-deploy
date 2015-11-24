#!/bin/bash
##### �ű��ڲ�������__��ͷ

__PWD=$(pwd)


# Ĭ�ϵ��ų��ļ��б�
__DEFAULT_EXCLUDE_FILE=${__PWD}/_build/.defaultExclude
__PROTOBUF_SCRIPT=${__PWD}/_build/protobuf.sh 
# ִ���Զ������Ե�ʱ�򣬱任Ŀ¼
if [ "$1" = "-t" ];then
		__DEFAULT_EXCLUDE_FILE=${__PWD}/../.defaultExclude
		__PROTOBUF_SCRIPT=${__PWD}/../protobuf.sh
fi


# �Զ�����Ҫ�ų����ļ��б� tar --exclude-from ֧�ֵĸ�ʽ���ļ�Ϊ'.exclude'
__EXCLUDE_FILE=${__PWD}/.exclude


# ����
__OUTPUT_DIR=${__PWD}/'output'
__DEPLOY_OFFLINE=$__OUTPUT_DIR/'deploy.offline'
__DEFAULT_DEPLOY_OFFLINE_PATH='/home/work/orp'


#������
rm -rf $__OUTPUT_DIR 
mkdir -p $__OUTPUT_DIR

# ������ʼ��
# ȡĬ�ϵ�ģ��������Ϊtar����
if [  ${#__PRODUCTS[@]} -eq 0 ];then
	echo -e "### __PRODUCTS δָ������Ҫǿ��ָ�� ### \r\n"
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

# �����߼���֧�ֶ��ģ����
if [ $__PRODUCTS_NUM -ne $__TAR_TARGETS_NUM ];then
	echo "__PRODUCTS=$__PRODUCTS_NUM �� __TAR_TARGETS=$__TAR_TARGETS_NUM ������ƥ�� "
	exit 1
else
	if [ $__OFFLINE_PATH_NUM -gt 0 ] && [ $__PRODUCTS_NUM -ne $__OFFLINE_PATH_NUM ] ;then
		echo "__PRODUCTS=$__TAR_TARGETS_NUM �� __OFFLINE_PATH=$__OFFLINE_PATH_NUM ������ƥ��"
		exit 1
	fi
fi


# ���²����ַ�ļ�����1
if [ $__OFFLINE_PATH_NUM -gt 0 ];then
	echo "[deployinfo]" >> $__DEPLOY_OFFLINE
fi

__PRODUCTS_PATH=()
for ((i = 0; i <= $__PRODUCTS_NUM -1; i++)); do
	echo -e "\r\n### ${__PRODUCTS[i]} ģ������ʼ ###"
	__PRODUCTS_PATH[$i]=$__OUTPUT_DIR/${__PRODUCTS[i]}'.tar.gz'

	# �л���tar�����Դ��ַ��Ŀ¼
	if [ "x$__TAR_SOURCE_ROOT_DIR" != "x" ];then			
		cd $__TAR_SOURCE_ROOT_DIR
	fi

	if [ -f $__EXCLUDE_FILE ] ;then
		tar -zcvf ${__PRODUCTS_PATH[i]} --exclude-from=$__DEFAULT_EXCLUDE_FILE --exclude-from=$__EXCLUDE_FILE ${__TAR_TARGETS[i]}

	else
		tar -zcvf ${__PRODUCTS_PATH[i]} --exclude-from=$__DEFAULT_EXCLUDE_FILE ${__TAR_TARGETS[i]}
	fi

	# �ص�ִ�нű���Ŀ¼
	if [ "x$__TAR_SOURCE_ROOT_DIR" != "x" ];then			
		cd -
	fi

	md5sum ${__PRODUCTS_PATH} > $__OUTPUT_DIR/${__PRODUCTS[i]}'.tar.gz.md5'

	# ���²����ַ�ļ�����
	if [ ${#__OFFLINE_PATH} -gt 0 ];then
		echo "${__PRODUCTS[i]}.tar.gz=${__OFFLINE_PATH[i]}" >> $__DEPLOY_OFFLINE
	fi
	echo -e "### ${__PRODUCTS[i]} ģ�������� ###\r\n"
done


# ����tar��
__TEST_DIR='.tempTest'
rm -rf $__TEST_DIR # ������ʱĿ¼��ͻ��ɾ���ϵ�Ŀ¼
mkdir -p $__TEST_DIR

for ((i = 0; i <= $__PRODUCTS_NUM -1; i++)); do
	tar xzvf ${__PRODUCTS_PATH[i]} -C $__TEST_DIR  1>/dev/null
done


rm -rf $__TEST_DIR
echo -e "�������"