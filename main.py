import datetime
import logging
import os
import requests
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QMessageBox
from lupa import LuaRuntime
from tinydb import TinyDB, Query


class Authority(QMessageBox):
    def __init__(self, metadata, name, risk, message):
        super().__init__()
        self.setWindowTitle("权限")
        self.setText("插件-{} 请求获取 {} 权限！".format(metadata["Name"], name))
        self.setInformativeText("风险等级: {}\n{}".format(risk, message))
        self.setIcon(QMessageBox.Warning)
        self.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)

    def get_button(self) -> bool:

        if self.exec_() == QMessageBox.Ok:

            return True
        else:
            return False


class LuaAPIS:
    def __init__(self, plugins: TinyDB):
        self.plugins: TinyDB = plugins
        self.pug = Query()

    @staticmethod
    def lua_func_example(arg1, arg2=None) -> tuple:
        """
        LuaID: _APP_EXAMPLE_FUNC

        这是给python lua api的示例函数，让开发者快速熟悉api的调用，可搭配APP_OPT一起使用！

        :param arg1: 示例必填参数
        :param arg2: 示例选填参数
        """

        return "Hello, World!", arg1, arg2

    @staticmethod
    def lua_func_opt(func, opt: dict):
        """
        LuaID: APP_OPT

        解决lua不能调用可选参数类型函数问题（通常用于与python交互的api中）！
        示例 (lua)：
        APP_OPT(_APP_EXAMPLE_FUNC, {arg1 = "你", arg2 = "好世界"})

        :param func: 函数
        :param opt: 参数键对
        :return: func return
        """

        return func(**opt)

    @staticmethod
    def lua_func_len(_list: list) -> int:
        """
        LuaID: LEN

        解决lua不能访问python list长度问题！

        :param _list:
        :return: int
        """

        return len(_list)

    def lua_func_fileio(self, metadata, **kwargs):
        """
        LuaID: fileio

        进行文件io交互（需要GetFileIO权限）
        示例（lua）：

        local file = APP_OPT(fileio, {file="test.txt", mode="w", metadata=MetaData, encoding="UTF-8"})
        if file then
            file.close()
        else
            GetFileIO(MetaData) -- 获取权限
        end

        :param metadata: lua metadata var
        :return: open()
        """

        if self.plugins.search(self.pug.name == metadata["Name"])[0]["authority"]["fileIO"] is False:
            return False

        self.LOG(metadata).debug("调用了写入权限("+str(kwargs)+")")
        return open(**kwargs)

    def lua_func_get_fileio(self, metadata) -> bool:
        """
        LuaID: GetFileIO

        获取fileio权限

        :param metadata: lua metadata var
        :return: bool
        """

        box = Authority(metadata, "FileIO", "较高", "该权限可以让插件在您的磁盘进行读取/写入。")
        box.show()

        if box.get_button():
            plugin_entry = self.plugins.get(self.pug.name == metadata["Name"])
            authority = plugin_entry.get('authority', {})
            authority['fileIO'] = True
            self.plugins.update({'authority': authority}, self.pug.name == metadata["Name"])

            return True

        return False

    def lua_func_run_python(self, metadata, code: str) -> bool:
        """
        LuaID: _APP_RUN_PYTHON

        在lua中运行python代码（需要GetRunPython权限）

        :param metadata: lua metadata var
        :param code: python code
        :return: bool
        """

        if self.plugins.search(self.pug.name == metadata["Name"])[0]["authority"]["runPythonCode"] is False:
            return False

        self.LOG(metadata).warning("调用了RunPythonCode权限({})".format(code))

        exec(code)
        return True

    def lua_func_get_run_python(self, metadata) -> bool:
        """
        LuaID: GetRunPython

        获取RunPython权限

        :param metadata: lua metadata var
        :return: bool
        """

        box = Authority(metadata, "RunPython", "病毒级", "该权限可以让插件在您的设备上运行任意python代码，"
                        "并且绕过内置权限系统。\n你应该清楚你要做什么！")
        box.show()

        if box.get_button():
            plugin_entry = self.plugins.get(self.pug.name == metadata["Name"])
            authority = plugin_entry.get('authority', {})
            authority['runPythonCode'] = True
            self.plugins.update({'authority': authority}, self.pug.name == metadata["Name"])
            return True

        return False

    def lua_func_os(self, metadata):
        """
        LuaID: os

        在lua中使用python os（需要System权限）

        :param metadata: lua metadata var
        :return: os
        """
        if self.plugins.search(self.pug.name == metadata["Name"])[0]["authority"]["System"] is False:
            return False

        self.LOG(metadata).warning("调用了System权限")

        return os

    def lua_func_get_system(self, metadata) -> bool:
        """
        LuaID: GetSystem

        获取System权限

        :param metadata: lua metadata var
        :return: bool
        """

        box = Authority(metadata, "System", "高", "该权限可以让插件在您的设备上调用系统功能。")
        box.show()

        if box.get_button():
            plugin_entry = self.plugins.get(self.pug.name == metadata["Name"])
            authority = plugin_entry.get('authority', {})
            authority['System'] = True
            self.plugins.update({'authority': authority}, self.pug.name == metadata["Name"])
            return True

        return False

    class LOG:
        """
        LuaID: LOG

        在写入LUA中写入日志
        """

        def __init__(self, metadata):
            self.name = metadata["Name"]

        def debug(self, msg):
            logging.debug("插件`" + self.name + "`: " + msg)

        def info(self, msg):
            logging.info("插件`" + self.name + "`: " + msg)

        def warning(self, msg):
            logging.warning("插件`" + self.name + "`: " + msg)

        def error(self, msg):
            logging.error("插件`" + self.name + "`: " + msg)

        def critical(self, msg):
            logging.critical("插件`" + self.name + "`: " + msg)


class MainAPP(QMainWindow):
    os.mkdir("logs") if not os.path.isdir("logs") else None
    logging.basicConfig(level=logging.DEBUG, format="[%(asctime)s - %(name)s | %(levelname)s]: %(message)s",
                        filename="logs/" + datetime.datetime.now().strftime("%Y-%m-%d-%H.%M.%S") + " APPRUN.log",
                        encoding="UTF-8")

    def __init__(self):

        super().__init__()

        logging.info("初始化PluginLoader:")

        logging.debug("初始化Lua")
        self.lua = LuaRuntime(unpack_returned_tuples=True)

        logging.debug("初始化数据库...")
        self.plugin_dir_path = "plugin/"
        self.plugins = TinyDB("data.json")
        self.pug = Query()
        self.LuaAPIS = LuaAPIS(self.plugins)

        self.init()
        self.load_plugins()

        super().show()

    def init(self):
        logging.debug("初始化文件夹...")
        for i in [self.plugin_dir_path, self.plugin_dir_path + ".temp", self.plugin_dir_path + ".config",
                  self.plugin_dir_path + ".PluginInternalStorage"]:
            os.mkdir(i) if not os.path.isdir(i) else None

        logging.debug("注入Lua APIs...")
        self.lua.globals().io, self.lua.globals().os = None, None  # 限制危险操作 < -and- v
        self.lua.globals().package = None

        # 遵循PEP8 E501 单行字符数量 < 120
        self.lua.globals().window, self.lua.globals().button = self, QPushButton  # 注册内部api < -and- v 7
        self.lua.globals().http, self.lua.globals()._APP_EXAMPLE_FUNC = requests, self.LuaAPIS.lua_func_example
        self.lua.globals().APP_OPT, self.lua.globals().fileio = self.LuaAPIS.lua_func_opt, self.LuaAPIS.lua_func_fileio
        self.lua.globals().GetFileIO, self.lua.globals().LOG = self.LuaAPIS.lua_func_get_fileio, self.LuaAPIS.LOG
        self.lua.globals()._APP_RUN_PYTHON = self.LuaAPIS.lua_func_run_python
        self.lua.globals().GetRunPython = self.LuaAPIS.lua_func_get_run_python
        self.lua.globals().os, self.lua.globals().GetSystem = self.LuaAPIS.lua_func_os, self.LuaAPIS.lua_func_get_system
        self.lua.globals().LEN = self.LuaAPIS.lua_func_len

        logging.info("PluginLoader初始化完成\n")

    def load_plugins(self):
        logging.info("加载Plugins:")
        loaded_plugins = 0
        for i in os.listdir(self.plugin_dir_path):
            file = open(self.plugin_dir_path + i, "r", encoding="UTF-8") if os.path.splitext(i)[1] == ".lua" else None
            if file is not None:
                logging.debug("加载: File `{}` Plugin...".format(os.path.splitext(i)[0]))

                try:
                    self.lua.execute(file.read())
                    data = self.lua.globals().PLUGIN_MetaData()
                    if self.plugins.search(self.pug.name == data[0]) == list():
                        self.plugins.insert({"name": data[0], "License": data[1], "authority": {"fileIO": False,
                                             "runPythonCode": False, "System": False}})

                    for _i in data[2]:
                        self.download_plugin(_i, data[2][_i]) if not os.path.isfile("plugin/"+_i+".lua") else None

                    self.lua.globals().Init()
                    loaded_plugins += 1
                    file.close()
                except Exception as error:
                    logging.error("加载`{}`插件时遇到错误！\n\t\t错误信息: {}".format(os.path.splitext(i)[0], error))
                    print(error)

        logging.info("加载完成(共计: {} 个Plugin(s))".format(loaded_plugins))

    @staticmethod
    def download_plugin(name, source):
        logging.info("下载依赖`{}`".format(name))
        if source == "main":
            logging.info("从`{}`源下载`{}`".format(name, source))
            r = requests.get("https://raw.gitcode.com/lvzhiyuan_0925/plugins/raw/main/{}".format(name+".lua"))
            with open("plugin/"+name+".lua", "w", encoding="UTF-8") as file:
                file.write(r.text)

        else:
            ...  # 等待增加从其他源下载


if __name__ == "__main__":
    app = QApplication([])

    window = MainAPP()  # 注意，因为PyQt特性，所有窗口都必须赋值为一个变量，否则会闪退！

    app.exec_()
