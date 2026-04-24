# 编译方法、技术与实践

赵雪东 231220011

---

## 一、功能说明

### 1.1 程序整体架构

本程序在实验一的基础上新增了语义分析模块。`syntax.y` 中所有产生式动作仅负责构造抽象语法树，不含任何语义逻辑；全部语义分析代码集中于 `semantic.c` 与 `semantic.h`，`main` 函数在 `yyparse()` 完成后调用 `semantic_analyze(root)` 启动语义分析。

### 1.2 符号表设计

符号表采用**线性链表**实现，全局头指针为 `symbol_table`，插入使用**头插法**（O(1)），查找从表头线性扫描（O(n)）。每个符号节点包含以下字段：

| 字段        | 类型              | 说明                                                    |
| ----------- | ----------------- | ------------------------------------------------------- |
| name[32]  | char[]          | 标识符名称                                              |
| kind      | enum SymbolKind | `SYM_VAR` / `SYM_FUNC` / `SYM_STRUCT_DEF` / `SYM_FIELD` |
| type      | Type            | 指向对应类型结构的指针                                  |
| is_active | int             | 预留字段，插入时置 1                                    |
| next      | SymbolNode      | 指向链表下一节点                                        |

符号种类共四类：`SYM_VAR`（普通变量）、`SYM_FUNC`（函数）、`SYM_STRUCT_DEF`（结构体定义）、`SYM_FIELD`（结构体域）。结构体域以独立种类插入全局符号表，与普通变量共享命名空间，实现假设 7（域不与变量重名、不同结构体域互不重名）的统一检查，无需维护额外的跨结构体比对数据结构。

符号表对外提供统一的查找接口 `lookup_symbol_for_def`，遍历整条链表，只要名字匹配即返回，用于定义阶段的重名检查与使用阶段的符号查找。

### 1.3 类型系统设计

类型系统由 `Type_` 与 `FieldList_` 两个结构体组成，统一表示 C−− 中所有类型：

```c
struct Type_ {
    enum Kind kind;   // BASIC / ARRAY / STRUCTURE / FUNCTION
    union {
        int basic;                              // 0=int, 1=float
        struct { Type elem; int size; } array;
        FieldList structure;                    // 结构体域链表
        struct { Type returnType;
                 FieldList params; } function;
    } u;
};

struct FieldList_ {
    char name[32];   // 域名或参数名
    Type type;       // 域/参数类型
    FieldList tail;  // 下一个域/参数
};
```

### 1.4 必做内容：17 种语义错误检测

| 错误类型 | 触发场景                   | 实现要点                                                                                                            |
| -------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| 类型 1   | 变量使用时未定义           | `process_Exp`（ID 无后继）：调用 `lookup_symbol_for_def`判断|
| 类型 2   | 函数调用时未定义           | `process_Exp`（ID LP）：调用 `lookup_symbol_for_def`，查不到时报错                                                  |
| 类型 3   | 变量重复定义               | `process_Dec` / `process_ExtDecList` / `process_ParamDec`：插表前调用 `lookup_symbol_for_def` 检查历史重名          |
| 类型 4   | 函数重复定义               | `process_FunDec`：插表前调用 `lookup_symbol_for_def` 检查重名                                                       |
| 类型 5   | 赋值两侧类型不匹配         | `process_Exp`（ASSIGNOP）及 `process_Dec`（初始化）：调用 `is_type_equal`                                           |
| 类型 6   | 赋值号左侧为右值           | `process_Exp`（ASSIGNOP）：通过 `is_left_val` 参数传递左值标志，左侧为 0 时报错                                     |
| 类型 7   | 操作数类型不匹配           | `process_Exp`（算术/逻辑运算）：检查两操作数均为 BASIC 且 `is_type_equal` 为真                                      |
| 类型 8   | return 类型不匹配          | `process_Stmt`（RETURN）：与全局 `current_return_type` 调用 `is_type_equal` 比对                                    |
| 类型 9   | 函数实参与形参不匹配       | `process_Exp`（函数调用）：逐项用 `is_type_equal` 比对，不匹配时输出含函数签名的详细信息                            |
| 类型 10  | 对非数组变量使用 […]     | `process_Exp`（LB）：检查左侧类型 `kind != ARRAY`，优先提取变量名生成具体信息                                       |
| 类型 11  | 对普通变量使用 (…)       | `process_Exp`（ID LP）：查表后检查 `kind != SYM_FUNC`                                                               |
| 类型 12  | 数组下标为非整数           | `process_Exp`（LB）：细化错误信息，见 1.5 节                                                                        |
| 类型 13  | 对非结构体变量使用 .     | `process_Exp`（DOT）：检查左侧类型 `kind != STRUCTURE`                                                              |
| 类型 14  | 访问结构体未定义的域       | `process_Exp`（DOT）：遍历 `FieldList` 查找域名，未找到时在消息中附带具体域名                                       |
| 类型 15  | 结构体域名重定义或域初始化 | `process_Dec`（`is_struct=1`）：调用 `lookup_symbol_for_def` 全局查重；检测 ASSIGNOP 子节点存在时报错               |
| 类型 16  | 结构体名与已有名字重复     | `process_Specifier`（OptTag）：重名时报错并释放已分配的 `Type` 内存，返回 NULL 阻止后续处理                         |
| 类型 17  | 使用未定义的结构体         | `process_Specifier`（Tag）：调用 `lookup_symbol_for_def` 查不到时报错                   |

### 1.5 选做要求 3.3：结构等价

本程序实现了要求 3.3，将结构体类型等价机制由名等价改为**结构等价**。所有类型比较统一通过 `is_type_equal` 函数完成：

- **BASIC**：比较 `basic` 字段（0=int，1=float）
- **ARRAY**：递归比较元素类型，不要求数组大小相同（与 C 语言标准一致）
- **STRUCTURE**：**不比较结构体名称**，按 FieldList 顺序逐个递归比较各域类型，域数量与类型须一一对应，实现结构等价语义
- **FUNCTION**：递归比较返回类型与参数链表

### 1.6 统一错误输出函数 `semantic_error`
 
所有语义错误的输出均通过统一的 `semantic_error(int type, int line, const char *msg)` 函数完成，格式严格遵照实验要求，各处检测到错误后只需传入错误类型编号、行号和说明文字，由该函数统一格式化输出，保证全程输出格式一致，不会出现遗漏句号或格式不符的情况。说明文字在各调用处按错误类型单独拼接，能够携带具体的标识符名称、函数签名、域名等上下文信息。



---

## 二、编译说明

使用实验要求的**Makefile**进行编译。或使用**逐行编译指令**：

```
bison -d syntax.y
flex scanner.l
gcc syntax.tab.c semantic.c -lfl -o cc
```

---



