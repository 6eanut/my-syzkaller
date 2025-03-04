## proc

```
"proc": per process int (see description below), type-options:
	value range start, how many values per process, underlying type
```

`proc` 类型的语法格式如下:

```
proc[start, count, underlying_type]
```

参数说明：

* **`start`** ：值范围的起始值
* **`count`** ：每个进程中可以生成的值的数量
* **`underlying_type`** ：基础类型（如 `int8`, `int16`, `int32`, `int64`, `intptr` 等）

`proc` 的工作方式：

* `proc` 类型的值是进程相关的，这意味着：
  * 在同一个进程中，`proc` 类型的值会保持一致
  * 在不同的进程中，`proc` 类型的值可能会不同
* 这种特性非常适合用于生成与进程相关的资源或标识符（例如端口号、文件描述符等）

`proc` 类型通常用于以下场景：

* **端口号分配** ：为每个进程分配一组唯一的端口号
* **文件描述符管理** ：为每个进程生成一组唯一的文件描述符
* **其他进程相关资源** ：任何需要在进程中保持一致，但在不同进程中独立的值
