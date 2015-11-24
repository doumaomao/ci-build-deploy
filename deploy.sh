echo "####### 检测环境密码 和 环境可用性 #######"                
sshpass -p test_passwd ssh test_machine



echo "####### 模块编译 #######"
                
cd ${WORKSPACE}/test_module_1
 build_source_code.py -x test_username -u ./ -m test_module_1 -c "export PATH=test_path && cd test_module_1 && sh build.sh" & 
 
wait

echo "####### 检测编译结果，如果未找到模块的编译信息,表明模块编译出错，请查看模块详细编译日志(搜索error信息）#######";
cd ${WORKSPACE}                
echo '' > build_info
grep PRODUCT_PATH ${WORKSPACE}/test_module_1/build_info >> build_info

if [ $? -ne 0 ]
then    
    echo "未获取到build_info,模块编译出错，请查看模块详细编译日志";
    exit -1;
fi
                
echo "####### 环境部署 #######"
sshpass -p test_passwd ssh test_machine  "cd /release;/bin/rm -rf *.errno; sh test_deploy.sh"