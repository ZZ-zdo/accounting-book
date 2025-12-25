```mermaid
usecaseDiagram
    actor Student as "学生 (Student)"
    actor Professor as "教授 (Professor)"
    actor Registrar as "教务处 (Registrar)"
    actor BillingSystem as "外部计费系统"

    package "课程注册管理系统" {
        usecase "登录" as UC_Login
        usecase "注册选课" as UC_Register
        usecase "修改选课" as UC_Modify
        usecase "维护课程目录" as UC_Catalog
        usecase "查看任教课程" as UC_ViewTeaching
        usecase "查看学生名单" as UC_ViewRoster
        usecase "检查课程人数/取消" as UC_CheckStatus
    }

    %% 关系定义
    
    %% 包含关系 (Include)
    UC_Register ..> UC_Login : <<include>>
    UC_Modify ..> UC_Login : <<include>>
    UC_Catalog ..> UC_Login : <<include>>
    UC_ViewTeaching ..> UC_Login : <<include>>
    UC_ViewRoster ..> UC_Login : <<include>>

    %% 参与者与用例的关联
    Student --> UC_Register
    Student --> UC_Modify
    
    Registrar --> UC_Catalog
    Registrar --> UC_CheckStatus

    Professor --> UC_ViewTeaching
    Professor --> UC_ViewRoster
    
    %% 交互关系
    %% 注意：这里使用了正确的 |标签| 语法
    UC_Register -->|触发计费| BillingSystem
    UC_CheckStatus -->|更新目录| UC_Catalog

```
