echo "####### ��⻷������ �� ���������� #######"                
sshpass -p test_passwd ssh test_machine



echo "####### ģ����� #######"
                
cd ${WORKSPACE}/test_module_1
 build_source_code.py -x test_username -u ./ -m test_module_1 -c "export PATH=test_path && cd test_module_1 && sh build.sh" & 
 
wait

echo "####### �������������δ�ҵ�ģ��ı�����Ϣ,����ģ����������鿴ģ����ϸ������־(����error��Ϣ��#######";
cd ${WORKSPACE}                
echo '' > build_info
grep PRODUCT_PATH ${WORKSPACE}/test_module_1/build_info >> build_info

if [ $? -ne 0 ]
then    
    echo "δ��ȡ��build_info,ģ����������鿴ģ����ϸ������־";
    exit -1;
fi
                
echo "####### �������� #######"
sshpass -p test_passwd ssh test_machine  "cd /release;/bin/rm -rf *.errno; sh test_deploy.sh"