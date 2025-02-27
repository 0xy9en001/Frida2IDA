from string import Template
import idaapi
import idc
import ida_name
import ida_lines
import os
import json
import datetime

from PyQt5 import QtCore
from PyQt5.Qt import QApplication
from PyQt5.QtWidgets import QDialog, QHBoxLayout, QVBoxLayout, QTextEdit, QDialogButtonBox, QLineEdit, QPushButton

# --------------------------------------------------------------------------
# 模板
# --------------------------------------------------------------------------
args_log_template = 'console.log("args[$index]: " + args[$index]);\n'

hook_func_template = """
function hook_func_$function_name(){
    var base_addr = Module.findBaseAddress("$so_name");

    Interceptor.attach(base_addr.add($offset), {
        onEnter(args) {
            console.log("call $function_name");
            $args
        },
        onLeave(retval) {
            $result
            console.log("leave $function_name");
        }
    });
}
"""

dump_template = """
function dump_$offset() {
    var base_addr = Module.findBaseAddress("$so_name");
    var dump_addr = base_addr.add($offset);
    console.log(hexdump(dump_addr, {length: $length}));
}
"""

get_imports_exports_template = """
function get_imports_exports_template() {
    // 获取目标模块
    var moduleName = "$so_name"; // 替换为你要 hook 的 SO 文件名
    var module = Process.getModuleByName(moduleName);

    if (module) {
        console.log("Module found: " + module.name);

        // 枚举导入表
        console.log("Imports:");
        module.enumerateImports().forEach(function (imp) {
            console.log("  " + imp.name + " @ " + imp.address);
        });

        // 枚举导出表
        console.log("Exports:");
        module.enumerateExports().forEach(function (exp) {
            console.log("  " + exp.name + " @ " + exp.address);
        });
    } else {
        console.log("Module not found: " + moduleName);
    }
}
"""

inline_hook_get_register = """
function inline_hook_get_register() {
    var soAddr = Module.findBaseAddress("$so_name");
    if (soAddr) {
        var func_addr = soAddr.add($offset);
        Java.perform(function () {
            Interceptor.attach(func_addr, {
                onEnter: function (args) {
                    console.log("$Xxx: " + this.context.$Xxx); //注意此时就没有args概念了 
                },
                onLeave: function (retval) {}
            })
        })
    }
}
"""

inline_hook_set_register = """
function inline_hook_set_register() {
    var soAddr = Module.findBaseAddress("$so_name");
    if (soAddr) {
        var func_addr = soAddr.add($offset);
        Java.perform(function () {
            Interceptor.attach(func_addr, {
                onEnter: function (args) {
                    console.log("$Xxx 修改前: " + this.context.$Xxx); //注意此时就没有args概念了
                    this.context.$Xxx = ptr($value);
                    console.log("$Xxx 修改完成: " + this.context.$Xxx) 
                },
                onLeave: function (retval) {}
            })
        })
    }
}
"""

inline_hook_template = """
function hook_$offset(){
    var base_addr = Module.findBaseAddress("$soName");

    Interceptor.attach(base_addr.add($offset), {
        onEnter(args) {
            console.log("call $offset");
            console.log(JSON.stringify(this.context));
        },
    });
}
"""

hook_linker_init_template = """
function hook_call_constructors() {
    // 初始化变量
    let get_soname = null;
    let call_constructors_addr = null;
    let hook_call_constructors_addr = true;
    // 根据进程的指针大小找到对应的linker模块
    let linker = null;
    if (Process.pointerSize == 4) {
        linker = Process.findModuleByName("linker");
    } else {
        linker = Process.findModuleByName("linker64");
    }
    // 枚举linker模块中的所有符号
    let symbols = linker.enumerateSymbols();
    for (let index = 0; index < symbols.length; index++) {
        let symbol = symbols[index];
        // 查找名为"__dl__ZN6soinfo17call_constructorsEv"的符号地址
        if (symbol.name == "__dl__ZN6soinfo17call_constructorsEv") {
            call_constructors_addr = symbol.address;
        // 查找名为"__dl__ZNK6soinfo10get_sonameEv"的符号地址，获取soname
        } else if (symbol.name == "__dl__ZNK6soinfo10get_sonameEv") {
            get_soname = new NativeFunction(symbol.address, "pointer", ["pointer"]);
        }
    }
    // 如果找到了所有需要的地址和函数
    if (hook_call_constructors_addr && call_constructors_addr && get_soname) {
        // 挂钩call_constructors函数
        Interceptor.attach(call_constructors_addr,{
            onEnter: function(args){
                // 从参数获取soinfo对象
                let soinfo = args[0];
                // 使用get_soname函数获取模块名称
                let soname = get_soname(soinfo).readCString();
                // 调用tell_init_info函数并传递一个回调，用于记录构造函数的调用信息
                tell_init_info(soinfo, new NativeCallback((count, init_array_ptr, init_func) => {
                    console.log(`[call_constructors] ${soname} count:${count}`);
                    console.log(`[call_constructors] init_array_ptr:${init_array_ptr}`);
                    console.log(`[call_constructors] init_func:${init_func} -> ${get_addr_info(init_func)}`);
                    // 遍历所有初始化函数，并打印它们的信息
                    for (let index = 0; index < count; index++) {
                        let init_array_func = init_array_ptr.add(Process.pointerSize * index).readPointer();
                        let func_info = get_addr_info(init_array_func);
                        console.log(`[call_constructors] init_array:${index} ${init_array_func} -> ${func_info}`);
                    }
                }, "void", ["int", "pointer", "pointer"]));
            }
        });
    }
}
"""

# --------------------------------------------------------------------------
# 功能集成
# --------------------------------------------------------------------------


def set_clipboard_data(data) -> bool:
    """
    将生成的Frida脚本复制到剪贴板
    """
    try:
        QApplication.clipboard().setText(data)
        print("生成的Frida脚本已复制到剪贴板！")
    except Exception as e:
        print(e)
        return False
    return True


def print_args(args_num):
    """
    根据参数个数返回参数打印脚本
    """
    # 如果args_num等于0则代表没有参数
    if not args_num:
        return "// no args"
    else:   # 不等于0则代表有参数
        # 导入模板
        temp = Template(args_log_template)
        # logtext用于接收替换过变量的模板
        logtext = ""
        for i in range(args_num):
            logtext += temp.substitute({
                "index": i
            })
            logtext += "\t\t\t"
        return logtext


def get_argnum_and_ret(address):
    """
    获取当前地址处所属函数的参数个数以及是否存在返回值
    """
    # 将地址处反汇编
    cfun = idaapi.decompile(address)
    # 获取参数个数
    args_num = len(cfun.arguments)
    ret = True

    dcl = ida_lines.tag_remove(cfun.print_dcl())
    # 如果是void或者void*则代表没有返回值
    if (dcl.startswith("void ") is True) & (dcl.startswith("void *") is False):
        ret = False
    return args_num, ret


class InputRegistersUI(QDialog):
    def __init__(self) -> None:
        super(InputRegistersUI, self).__init__()
        # 界面初始化
        self.setWindowTitle("Please enter the register")
        self.setFixedWidth(600)
        self.input_text = ""
        # 创建控件
        self.edit_template = QLineEdit()
        self.edit_template.setClearButtonEnabled(True)
        self.edit_template.setPlaceholderText("eg: x0 x1 x2 x3....")
        # 按钮布局
        btn_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btn_box.setCenterButtons(True)
        # 连接信号
        btn_box.accepted.connect(self.accepted)
        btn_box.rejected.connect(self.rejected)
        # 布局设置
        layout = QVBoxLayout()
        layout.addWidget(self.edit_template)
        layout.addWidget(btn_box)
        self.setLayout(layout)

    def accepted(self):
        """
        自定义接受时的处理程序
        """
        self.input_text = self.edit_template.text().strip()
        self.accept()

    def rejected(self):
        """
        自定义取消时的处理程序
        """
        self.close()

    def get_input(self):
        """
        获取输入
        """
        return self.input_text


class InputValueUI(QDialog):
    def __init__(self) -> None:
        super(InputValueUI, self).__init__()
        # 界面初始化
        self.setWindowTitle("Please enter the value for register")
        self.setFixedWidth(600)
        self.input_text = ""
        # 创建控件
        self.edit_template = QLineEdit()
        self.edit_template.setClearButtonEnabled(True)
        self.edit_template.setPlaceholderText("eg: 0 1 2 3....")
        # 按钮布局
        btn_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btn_box.setCenterButtons(True)
        # 连接信号
        btn_box.accepted.connect(self.accepted)
        btn_box.rejected.connect(self.rejected)
        # 布局设置
        layout = QVBoxLayout()
        layout.addWidget(self.edit_template)
        layout.addWidget(btn_box)
        self.setLayout(layout)

    def accepted(self):
        """
        自定义接受时的处理程序
        """
        self.input_text = self.edit_template.text().strip()
        self.accept()

    def rejected(self):
        """
        自定义取消时的处理程序
        """
        self.close()

    def get_input(self):
        """
        获取输入
        """
        return self.input_text


class MenuActionHandler(idaapi.action_handler_t):
    """
    右键菜单项的动作处理器。
    """

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    @classmethod
    def get_name(cls):
        """
        返回对象的类名，必须和其它的不一样
        """
        return cls.__name__

    @classmethod
    def get_label(cls):
        """
        返回对象的标签，是给用户看的
        """
        return cls.label

    @classmethod
    def register(cls, plugin, label):
        """
        用来注册功能
        """
        cls.plugin = plugin
        cls.label = label
        instance = cls()  # 在类的内部创建当前类的实例
        return idaapi.register_action(idaapi.action_desc_t(  # 注册功能
            cls.get_name(),  # 名称
            instance.get_label(),  # 标签
            instance  # 处理程序
        ))

    @classmethod
    def unregister(cls):
        """
        取消注册后，该类将无法使用
        """
        idaapi.unregister_action(cls.get_name())

    @classmethod
    def activate(cls, ctx):
        """
        当用户点击菜单项时调用
        """
        return 1

    @classmethod
    def update(cls, ctx):
        """
        更新菜单项的状态（是否可用）
        """
        try:
            if idaapi.IDA_SDK_VERSION >= 900:
                # IDA 9.0以来, form_type被弃用了, 要换成widget_type
                # 汇编模式下才可以用
                if ctx.widget_type == idaapi.BWN_DISASM:
                    return idaapi.AST_ENABLE_FOR_FORM
                else:
                    return idaapi.AST_DISABLE_FOR_FORM
            else:
                if ctx.form_type == idaapi.BWN_DISASM:
                    return idaapi.AST_ENABLE_FOR_FORM
                else:
                    return idaapi.AST_DISABLE_FOR_FORM
        except Exception as e:
            # 为 IDA 版本 >= 7.0 的主菜单添加例外情况
            return idaapi.AST_ENABLE_ALWAYS


class F2I_hook_func(MenuActionHandler):
    """
    生成Frida function hook片段
    """
    def activate(self, ctx):
        self.plugin.hook_func()
        return 1


class F2I_get_dump_script(MenuActionHandler):
    """
    生成Frida dump片段
    """
    def activate(self, ctx):
        if idaapi.IDA_SDK_VERSION >= 700:
            if ctx.widget_type == idaapi.BWN_DISASM:
                self.plugin.get_dump_script()
                return 1
        else:
            if ctx.form_type == idaapi.BWN_DISASM:
                self.plugin.get_dump_script()
                return 1


class F2I_get_imports_exports(MenuActionHandler):
    """
    生成导入导出表
    """
    def activate(self, ctx):
        self.plugin.get_imports_exports()
        return 1


class F2I_inline_hook_get_register(MenuActionHandler):
    """
    获取地址处指定寄存器的值
    """
    def activate(self, ctx):
        self.plugin.inline_hook_get_register()
        return 1


class F2I_inline_hook_set_register(MenuActionHandler):
    """
    修改地址处指定寄存器的值
    """
    def activate(self, ctx):
        self.plugin.inline_hook_set_register()
        return 1

class F2I_hook_linker_init(MenuActionHandler):
    """
    生成hook linker的Frida脚本
    """
    def activate(self, ctx):
        self.plugin.get_hook_linker_init_script()
        return 1

class Hook(idaapi.UI_Hooks):
    # ida版本过高时，开始放弃使用form_type而是widget_type
    if idaapi.IDA_SDK_VERSION >= 700:
        def finish_populating_widget_popup(self, form, popup):
            if idaapi.get_widget_type(form) == idaapi.BWN_DISASM:
                try:
                    idaapi.attach_action_to_popup(form, popup, F2I_hook_func.get_name(), 'Frida2IDA/')
                    idaapi.attach_action_to_popup(form, popup, F2I_get_dump_script.get_name(), 'Frida2IDA/')
                    idaapi.attach_action_to_popup(form, popup, F2I_hook_linker_init.get_name(), 'Frida2IDA/')
                    idaapi.attach_action_to_popup(form, popup, F2I_inline_hook_get_register.get_name(), 'Frida2IDA/')
                    idaapi.attach_action_to_popup(form, popup, F2I_inline_hook_set_register.get_name(), 'Frida2IDA/')
                    idaapi.attach_action_to_popup(form, popup, F2I_get_imports_exports.get_name(), 'Frida2IDA/')
                except:
                    pass
    else:
        def finish_populating_tform_popup(self, form, popup):
            if idaapi.get_tform_type(form) == idaapi.BWN_DISASM:
                try:
                    idaapi.attach_action_to_popup(form, popup, F2I_hook_func.get_name(), 'Frida2IDA/')
                    idaapi.attach_action_to_popup(form, popup, F2I_get_dump_script.get_name(), 'Frida2IDA/')
                    idaapi.attach_action_to_popup(form, popup, F2I_hook_linker_init.get_name(), 'Frida2IDA/')
                    idaapi.attach_action_to_popup(form, popup, F2I_inline_hook_get_register.get_name(), 'Frida2IDA/')
                    idaapi.attach_action_to_popup(form, popup, F2I_inline_hook_set_register.get_name(), 'Frida2IDA/')
                    idaapi.attach_action_to_popup(form, popup, F2I_get_imports_exports.get_name(), 'Frida2IDA/')
                except:
                    pass


# 检查是否已经初始化 Frida2IDA 插件了
f2i_initialized = False


# --------------------------------------------------------------------------
# Plugin_t
# --------------------------------------------------------------------------
class Frida2IDA_Plugin_t(idaapi.plugin_t):
    # 插件信息
    flags = idaapi.PLUGIN_KEEP  # 表示插件初始化成功，IDA 应该保持插件加载状态
    comment = "Frida2IDA plugin for IDA Pro"
    help = "Find more information on Frida2IDA at "
    wanted_name = "Frida2IDA"
    wanted_hotkey = "Alt-F1"

    def init(self):
        """
        插件初始化方法，在插件加载时调用。
        """
        global f2i_initialized
        # 注册弹出菜单（右键菜单）句柄
        try:
            F2I_hook_func.register(self, "生成Frida func hook片段")
            F2I_get_dump_script.register(self, "生成Frida dump片段")
            F2I_hook_linker_init.register(self, "生成Frida init片段")
            F2I_inline_hook_get_register.register(self, "生成Frida register dump片段")
            F2I_inline_hook_set_register.register(self, "生成Frida register modify片段")
            F2I_get_imports_exports.register(self, "生成获取导入导出表片段")
        except:
            pass

        # 设置弹出菜单（右键菜单）
        self.hooks = Hook()
        self.hooks.hook()

        # 设置弹出菜单（导航栏菜单）
        if not f2i_initialized:
            f2i_initialized = True
            # 判断ida版本
            if idaapi.IDA_SDK_VERSION >= 700:
                idaapi.attach_action_to_menu("Edit/Frida2IDA/生成Frida func hook片段", F2I_hook_func.get_name(), idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/Frida2IDA/生成Frida dump片段", F2I_get_dump_script.get_name(), idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/Frida2IDA/生成Frida init片段", F2I_hook_linker_init.get_name(), idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/Frida2IDA/生成Frida register dump片段", F2I_inline_hook_get_register.get_name(), idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/Frida2IDA/生成Frida register modify片段", F2I_inline_hook_set_register.get_name(), idaapi.SETMENU_APP)
                idaapi.attach_action_to_menu("Edit/Frida2IDA/生成导入导出表", F2I_get_imports_exports.get_name(), idaapi.SETMENU_APP)
            else:
                menu = idaapi.add_menu_item("Edit/Frida2IDA/", "生成Frida func hook片段", "", 1, self.hook_func, None)
                if menu is not None:
                    idaapi.add_menu_item("Edit/Frida2IDA/", "生成Frida dump片段", "", 1, self.get_dump_script, None)
                    idaapi.add_menu_item("Edit/Frida2IDA/", "生成Frida init片段", "", 1, self.get_hook_linker_init_script, None)
                    idaapi.add_menu_item("Edit/Frida2IDA/", "生成Frida register dump片段", "", 1, self.inline_hook_get_register, None)
                    idaapi.add_menu_item("Edit/Frida2IDA/", "生成Frida register modify片段", "", 1, self.inline_hook_set_register, None)
                    idaapi.add_menu_item("Edit/Frida2IDA/", "生成导入导出表", "", 1, self.get_imports_exports, None)
                elif idaapi.IDA_SDK_VERSION < 680:
                    # older IDAPython (such as in IDAPro 6.6) does add new submenu.
                    # in this case, put Keypatch menu in menu Edit \ Patch program
                    # not sure about v6.7, so to be safe we just check against v6.8
                    idaapi.add_menu_item("Edit/Patch program/", "-", "", 0, self.menu_null, None)
                    idaapi.add_menu_item("Edit/Patch program/", "Frida2IDA:: 生成Frida func hook片段", "", 0, self.hook_func, None)
                    idaapi.add_menu_item("Edit/Patch program/", "Frida2IDA:: 生成Frida dump片段", "", 0, self.get_dump_script, None)
                    idaapi.add_menu_item("Edit/Patch program/", "Frida2IDA:: 生成Frida init片段", "", 0, self.get_hook_linker_init_script, None)
                    idaapi.add_menu_item("Edit/Patch program/", "Frida2IDA:: 生成Frida register dump片段", "", 0, self.inline_hook_get_register, None)
                    idaapi.add_menu_item("Edit/Patch program/", "Frida2IDA:: 生成Frida register modify片段", "", 0, self.inline_hook_set_register, None)
                    idaapi.add_menu_item("Edit/Patch program/", "Frida2IDA:: 生成导入导出表", "", 0, self.get_imports_exports, None)

        print("=" * 80)
        print("Frida2IDA is loaded")
        print("Find more information on Frida2IDA at https://github.com/0xy9en001/Frida2IDA")
        print("=" * 80)
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        插件运行方法，当用户触发插件时调用。
        """
        idaapi.msg("Frida2IDA is running.\n")

    def term(self):
        """
        插件清理方法，在插件卸载时调用。
        """
        idaapi.msg("Frida2IDA is terminating.\n")

    def menu_null(self):
        """
        空句柄
        """
        pass

    def hook_func(self):
        """
        生成Frida func hook片段
        """
        # 获取当前光标地址
        ea_addr = idaapi.get_screen_ea()
        # 获取当前光标地址所指函数的上边界（idc.FUNCATTR_START指明上边界）
        start_address = idc.get_func_attr(ea_addr, idc.FUNCATTR_START)
        # 检查当前光标地址处是否在函数内
        if start_address == idc.BADADDR:
            print("当前传入的地址不在函数内..idc.BADADDR", start_address)
        else:
            # 获取so名称
            so_name = idaapi.get_root_filename()
            # 获取函数名
            function_name = idaapi.get_func_name(start_address)
            # 获取当前函数的参数数量和是否有返回值
            args_num, ret = get_argnum_and_ret(start_address)
            # 生成参数打印脚本
            print_args_text = print_args(args_num)
            # 生成返回值打印模板
            print_ret_text = 'console.log("retval: " + retval);' if ret else "// no return"
            # 获取函数偏移(需要注意是Arm还是Thumb)
            # offset = start_address if idaapi.get_inf_structure().is_64bit() else (start_address + idc.get_sreg(start_address, "T"))
            # 导入模板
            temp = Template(hook_func_template)
            # 替换模板内参数
            script = temp.substitute({
                "so_name": so_name,
                "function_name": function_name,
                "offset": hex(start_address),
                "args": print_args_text,
                "result": print_ret_text,
            })
            # 将Frida脚本复制进剪贴板
            set_clipboard_data(script)

    def get_dump_script(self):
        """
        生成Frida dump脚本
        """
        # 获取so名称
        so_name = idaapi.get_root_filename()
        # 获取起始地址
        start = idc.read_selection_start()
        # 获取结尾地址
        end = idc.read_selection_end()
        if (start != idaapi.BADADDR) and (end != idaapi.BADADDR):
            # 计算需要dump的长度
            length = end - start
            # 导入模板
            temp = Template(dump_template)
            # 替换模板中的参数
            script = temp.substitute({
                "so_name": so_name,
                "offset": hex(start),
                "length": hex(length),
            })
            # 将Frida脚本复制到剪贴板
            set_clipboard_data(script)

    def get_imports_exports(self):
        """
        生成导入导出表
        """
        # 获取so名称
        so_name = idaapi.get_root_filename()
        # 导入模板
        temp = Template(get_imports_exports_template)
        # 替换模板内参数
        script = temp.substitute({
            "so_name": so_name,
        })
        # 将Frida脚本复制进剪贴板中
        set_clipboard_data(script)

    def inline_hook_get_register(self):
        """
        获取地址处寄存器的值
        """
        # 获取so名称
        so_name = idaapi.get_root_filename()
        # 获取当前光标地址
        ea_addr = idaapi.get_screen_ea()
        # 获取要修改的寄存器
        Xxx_input = InputRegistersUI()
        result = Xxx_input.exec_()
        if result == QDialog.Accepted:
            Xxx = Xxx_input.get_input()
        else:
            return
        # 导入模板
        temp = Template(inline_hook_get_register)
        # 替换模板内参数
        script = temp.substitute({
            "so_name": so_name,
            "offset": hex(ea_addr),
            "Xxx": Xxx,
        })
        # 将Frida脚本复制进剪贴板中
        set_clipboard_data(script)


    def inline_hook_set_register(self):
        """
        获取地址处寄存器的值
        """
        # 获取so名称
        so_name = idaapi.get_root_filename()
        # 获取当前光标地址
        ea_addr = idaapi.get_screen_ea()
        # 要修改的寄存器
        Xxx_input = InputRegistersUI()
        result = Xxx_input.exec_()
        if result == QDialog.Accepted:
            Xxx = Xxx_input.get_input()
        else:
            return
        # 要修改的值
        value_input = InputValueUI()
        result = value_input.exec_()
        if result == QDialog.Accepted:
            value = value_input.get_input()
        else:
            return
        # 导入模板
        temp = Template(inline_hook_set_register)
        # 替换模板内参数
        script = temp.substitute({
            "so_name": so_name,
            "offset": hex(ea_addr),
            "Xxx": Xxx,
            "value": value,
        })
        # 将Frida脚本复制进剪贴板中
        set_clipboard_data(script)

    def get_hook_linker_init_script(self):
        """
        获取hook_Linker的Frida脚本
        """
        set_clipboard_data(hook_linker_init_template)

# 注册IDA插件
def PLUGIN_ENTRY():
    return Frida2IDA_Plugin_t()
