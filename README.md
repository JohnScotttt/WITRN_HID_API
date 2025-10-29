# 基于Python的WITRN HID通用API

![version](https://img.shields.io/badge/Versio-1.0.0-green)

## 项目介绍

该项目提供面向Python的接收WITRN HID数据流的通用API，仅需要pip安装即可使用。

当前版本为预览版，可能存在许多问题，您可以向本项目反馈issue，暂不接受PR，感谢您的支持。

## 项目进度&画饼

已完成所有PD报文解析！正式进入Debug阶段。

## 使用

推荐通过PyPI安装，仅需要在需要的环境中

```cmd
pip install witrnhid
```

或从GitHub下载源文件解压，或是git clone

```cmd
cd WITRN_HID_API
pip install .
```

本项目会自动安装成，在您的项目中导入

```python
import witrnhid
```

即可开箱使用。

## 数据结构

请仔细阅读以下内容确保您能正确的调用API。

本项目推荐使用的接口仅metadata类和WITRN_HID类两个。

### 元数据 metadata类

任何经过解析的内容都将以元数据进行打包，元数据的基本结构如下

| 属性    | 类型  | 作用                                 |
| ------- | ----- | ------------------------------------ |
| raw     | str   | 当前元数据的二进制值                 |
| bit_loc | tuple | 当前元数据在上一层的比特位置         |
| field   | str   | 当前元数据字段名                     |
| value   | any   | 当前元数据字段值或是下一层元数据list |

您可以使用 `raw()` 、 `bit_loc()` 、 `field()` 、 `value()` 四个函数来调取他们的内容。

当您 `print()` 一个metadata类时，它将默认返回`value` 的内容；当您请求了metadata类的可重建描述时，它将默认返回 `field` : `value` 组成的字符串。

您可以对任意 `value` 为元数据list的元数据使用[index]或[field]来获取list中的元数据，其中field为想要获取的元数据的 `field` 。

### 常规HID消息

| bit_loc  | field   | value                  |
| -------- | ------- | ---------------------- |
| (0, 511) | general | 常规消息（元数据list） |

常规HID消息解析时，每条消息将打包成一个元数据，其 `raw` 保存二进制值， `bit_loc` 保存(0, 511)即整条HID消息的从头到尾的比特位置， `field` 固定保存"general"， `value` 保存一个元数据list。

常规HID消息的 `value` 进行下一步解析，组成Ah、Wh、记录时长等的元数据 list，list中的每个元数据的 `raw` 保存该元数据的原始二进制值， `bit_loc` 保存该元数据在HID消息所占的比特位置，`field`保存该元数据的字段名， `value` 保存该元数据的字段值。例如保存Ah的元数据为：

```
raw = '01000001011000011101001101101011'
bit_loc = (112, 143)
field = 'Ah'
value = '14.114115715026855Ah'
```

### PD HID消息

由于本项目使用大量元数据嵌套结构，如果您并不是非常了解PD数据结构，建议您对任何元数据使用 `value()` 来获取其内容，根据其是否为元数据list进行下一步操作。

下面的话我自己也不知道在说什么，但是大体正确。

用文字描述PD HID消息的层级结构过于复杂也难以理解，简单来说任何数据都将以元数据格式打包，最小元数据单位即 `field` 为字段名、 `value` 为字段值。若干最小元数据构成一个数据包，该数据包也由元数据打包， `field` 为数据包名， `value` 为最小元数据list。若干数据包组合成更大的数据包结构，同样也由元数据打包，结构相同。如果您要具体的字段值，就要从大到小按层调取。

PD HID消息将按层解析，第一层为HID消息层

| bit_loc               | field | value                |
| --------------------- | ----- | -------------------- |
| 有效的所有HID比特位置 | pd    | PD消息（元数据list） |

该层 `value` 包含3或4或5个元数据的list，组成第二层PD消息层，具体如下

| field                     | value                        |
| ------------------------- | ---------------------------- |
| Length                    | PD消息长度                   |
| SOP*                      | SOP类型                      |
| Message Header            | PD消息头（元数据list）       |
| [Extended Message Header] | [PD扩展消息头（元数据list）] |
| [Data Objects/Data Block] | [PD消息数据（元数据list）]   |

需要注意的是PD消息的单个逻辑内容是以小端存储，但是整条PD消息又是以大端存储，所以除非是单个逻辑内容的 `raw` 将以小端转换成二进制值，否则 `raw` 将以大端转换成二进制值。以第二层为例，Length字段的 `raw` 将以小端转换，但是Message Header字段的 `raw` 将以大端转换。

```
小端转换：0x14A5 -> 0b1010010100010100
大端转换：0x14A5 -> 0b0001010010100101
```

Message Header、[Extended Message Header]、[Data Objects/Data Block]的 `value` 均属于第三层。从本层开始， `bit_loc` 、 `field` 、 `value` 将严格按照USB-IF制定的PD规范来解析， `value` 的具体值将解析成可用值，例如电压电流值（带单位，str类型），Data Objects数量（int类型），是否扩展（bool类型），如果您需要二进制、十进制、十六进制值，可以直接从 `raw` 转换取得，注意前文提到的大小端问题。

第三层中只有[Data Objects/Data Block]的 `value` 包含第四层，不过内容复用度低且复杂，具体参考PD规范。

### WITRN_HID类

若要链接WITRN HID设备读取HID流并解包，需要您创建 `WITRN_HID` 类实例。该类结构实现不需要您掌握，其提供6种可调用方法。注意从pre 0.3.0版本开始不再支持创建实例时自动连接设备，需要手动连接。

```python
dev = WITRN_HID()
```

`open()` 方法允许您使用无参数方法连接K2设备，也可以传入int类型的vid、pid连接自定义设备，或者是传入bytes类型的path连接自定义设备。

```python
dev.open()
dev.open(vid: int, pid: int)
dev.open(path: bytes)
```

`read_data()` 方法将获取从当前时刻后HID流中的第一个完整HID消息，返回uint8 list，并且在实例内默认保存获取时刻的时间戳（分辨率0.001s）和HID消息内容，保存到下次调用该方法时被覆盖。实例不会为您维护一个HID消息缓存栈，请您自行维护。

`general_unpack()` 方法将解析常规HID消息，如果不提供参数则默认解析实例内保存的HID消息，返回读到消息时的时间戳和解析完的元数据；如果提供64长度的uint8 list将会解析提供的内容，返回调用函数时的时间戳和解析完的元数据。

`pd_unpack()` 方法将解析PD HID消息，如果不提供参数则默认解析实例内保存的HID消息，返回读到消息时的时间戳和解析完的元数据；如果提供64长度的uint8 list将会解析提供的内容，返回调用函数时的时间戳和解析完的元数据。如您自行维护消息栈，需要按需同时提供 `last_pdo` 、 `last_ext` 和 `last_rdo` （均以metadata类）保证解析的正确性，其中 `last_pdo` 为可能的Request消息提供PDO信息， `last_ext` 为可能的分包的Extended消息提供上下文， `last_rdo` 为可能的Status消息提供RDO信息。

`auto_unpack()` 方法将自动分析HID消息类型并解析，如果不提供参数则默认解析实例内保存的HID消息，返回读到消息时的时间戳和解析完的元数据；如果提供64长度的uint8 list将会解析提供的内容，返回调用函数时的时间戳和解析完的元数据。如您自行维护消息栈，需要按需同时提供 `last_pdo` 、 `last_ext` 和 `last_rdo` （均以 `metadata` 类型）保证解析的正确性，其中 `last_pdo` 为可能的Request消息提供PDO信息， `last_ext` 为可能的分包的Extended消息提供上下文， `last_rdo` 为可能的Status消息提供RDO信息。

注意，本API不会严格检查消息的正确性，如果解析失败则会直接覆写 `value` 为消息的十六进制值，如需查看失败报错则打开debug模式。

`close()` 方法将关闭实例的HID连接。

### Debug

创建实例时将 `debug` 传参设置为True

```python
dev = WITRN_HID(debug=True)
```

即可开启解析时break debug。

### 一些工具函数

从pre 0.2.1版本开始本项目还提供三个工具函数，分别是 `is_pdo(msg)` 、 `is_rdo(msg)` 、 `provide_ext(msg)` 。

#### is_pdo(msg)

该函数接收一个metadata类，判断其是否是一个PDO报文，返回bool类型。

#### is_rdo(msg)

该函数接收一个metadata类，判断其是否是一个RDO报文，返回bool类型。

#### provide_ext(msg)

该函数接收一个metadata类，判断其是否为有效的Extended消息的上下文，返回bool类型。无需担心解析时的上下文判断，该逻辑已经在Extended消息解析时自动判断。

如果您需要自己维护消息栈，推荐在每一条PD消息解析完后添加如下判断

```python
if is_pdo(msg):
    last_pdo = msg
if provide_ext(msg):
    last_ext = msg
if is_rdo(msg):
    last_rdo = msg
```

并且始终为解析提供这三个元数据，如此能保证解析的相对正确性。

Q：为什么不将判断写入WITRN_HID？

A：事实上默认的流式解析是包含判断逻辑的，但是并不维护消息栈。而通过传参的方式解析不应该影响类的内部变量，所以需要通过外部判断。

## License

从1.0.0版本开始本项目许可证由GPL变更为LGPL许可证。旧版本代码仍遵循GPL协议。
