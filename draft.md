```mermaid
useCaseDiagram
    actor "学生 (Student)" as Student
    actor "教授 (Professor)" as Professor
    actor "教务处/注册人员 (Registrar)" as Registrar
    actor "外部计费系统 (Billing System)" as BillingSystem

    package "课程注册管理系统 (Course Registration System)" {
        usecase "登录 (Login)" as UC_Login
        
        usecase "注册选课 (Register for Courses)" as UC_Register
        usecase "修改选课 (Modify Schedule)" as UC_Modify
        usecase "建立/维护课程目录 (Maintain Course Catalog)" as UC_Catalog
        
        usecase "查看任教课程 (View Teaching Schedule)" as UC_ViewTeaching
        usecase "查看学生名单 (View Student Roster)" as UC_ViewRoster
        
        usecase "检查课程人数/关闭课程 (Check Enrollment & Cancel Courses)" as UC_CheckStatus
        usecase "发送交款通知 (Send Billing Notification)" as UC_Bill
    }

    %% 关系定义
    
    %% 包含关系 (Include): 几乎所有操作都需要先登录
    UC_Register ..> UC_Login : <<include>>
    UC_Modify ..> UC_Login : <<include>>
    UC_Catalog ..> UC_Login : <<include>>
    UC_ViewTeaching ..> UC_Login : <<include>>
    UC_ViewRoster ..> UC_Login : <<include>>

    %% 参与者与用例的关联
    Student --> UC_Register
    Student --> UC_Modify
    
    Registrar --> UC_Catalog
    Registrar --> UC_CheckStatus : (需求4: 管理课程取消)

    Professor --> UC_ViewTeaching
    Professor --> UC_ViewRoster
    
    %% 扩展/关联关系
    %% 选课注册成功后，触发外部计费系统
    UC_Register --> BillingSystem : 触发计费 (需求5)
    
    %% 需求4中少于3人取消课程，这可能作为维护目录的一部分，或者独立流程
    UC_CheckStatus --> UC_Catalog : 更新目录状态

```
