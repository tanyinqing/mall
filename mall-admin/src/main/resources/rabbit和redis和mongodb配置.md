



# mall-admin

## application

```java
spring:
  profiles:
    active: dev #默认为开发环境
  servlet:
    multipart:
      enabled: true #开启文件上传
      max-file-size: 10MB #限制文件上传大小为10M

mybatis:
  mapper-locations:
    - classpath:dao/*.xml
    - classpath*:com/**/mapper/*.xml

jwt:
  tokenHeader: Authorization #JWT存储的请求头
  secret: mall-admin-secret #JWT加解密使用的密钥
  expiration: 604800 #JWT的超期限时间(60*60*24*7)
  tokenHead: Bearer  #JWT负载中拿到开头

redis:
  database: mall
  key:
    admin: 'ums:admin'
    resourceList: 'ums:resourceList'
  expire:
    common: 86400 # 24小时

secure:
  ignored:
    urls: #安全路径白名单
      - /swagger-ui.html
      - /swagger-resources/**
      - /swagger/**
      - /**/v2/api-docs
      - /**/*.js
      - /**/*.css
      - /**/*.png
      - /**/*.ico
      - /webjars/springfox-swagger-ui/**
      - /actuator/**
      - /druid/**
      - /admin/login
      - /admin/register
      - /admin/info
      - /admin/logout
      - /minio/upload

aliyun:
  oss:
    endpoint: oss-cn-shenzhen.aliyuncs.com # oss对外服务的访问域名
    accessKeyId: test # 访问身份验证中用到用户标识
    accessKeySecret: test # 用户用于加密签名字符串和oss用来验证签名字符串的密钥
    bucketName: macro-oss # oss的存储空间
    policy:
      expire: 300 # 签名有效期(S)
    maxSize: 10 # 上传文件大小(M)
    callback: http://39.98.190.128:8080/aliyun/oss/callback # 文件上传成功后的回调地址
    dir:
      prefix: mall/images/ # 上传文件夹路径前缀

minio:
  endpoint: http://192.168.3.101:9090 #MinIO服务所在地址
  bucketName: mall #存储桶名称
  accessKey: minioadmin #访问的key
  secretKey: minioadmin #访问的秘钥

logging:
  level:
    root: info #日志配置DEBUG,INFO,WARN,ERROR
    com.macro.mall: debug
#  file: demo_log.log #配置日志生成路径
#  path: /var/logs #配置日志文件名称
```

## application-dev redis

```java
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/mall?useUnicode=true&characterEncoding=utf-8&serverTimezone=Asia/Shanghai
    username: root
    password: system
    druid:
      initial-size: 5 #连接池初始化大小
      min-idle: 10 #最小空闲连接数
      max-active: 20 #最大连接数
      web-stat-filter:
        exclusions: "*.js,*.gif,*.jpg,*.png,*.css,*.ico,/druid/*" #不统计这些请求数据
      stat-view-servlet: #访问监控网页的登录用户名和密码
        login-username: druid
        login-password: druid
  redis:
    host: localhost # Redis服务器地址
    database: 0 # Redis数据库索引（默认为0）
    port: 6379 # Redis服务器连接端口
    password: # Redis服务器连接密码（默认为空）
    timeout: 300ms # 连接超时时间（毫秒）
```

# mall-portal

## application-dev

```java
server:
  port: 8085

spring:
  datasource:
    url: jdbc:mysql://localhost:3306/mall?useUnicode=true&characterEncoding=utf-8&serverTimezone=Asia/Shanghai
    username: root
    password: system
    druid:
      initial-size: 5 #连接池初始化大小
      min-idle: 10 #最小空闲连接数
      max-active: 20 #最大连接数
      web-stat-filter:
        exclusions: "*.js,*.gif,*.jpg,*.png,*.css,*.ico,/druid/*" #不统计这些请求数据
      stat-view-servlet: #访问监控网页的登录用户名和密码
        login-username: druid
        login-password: druid

  data:
    mongodb:
      host: localhost
      port: 27017
      database: mall-port

  redis:
    host: localhost # Redis服务器地址
    database: 0 # Redis数据库索引（默认为0）
    port: 6379 # Redis服务器连接端口
    password: # Redis服务器连接密码（默认为空）
    timeout: 300ms # 连接超时时间（毫秒）

  rabbitmq:
    host: localhost
    port: 5672
    virtual-host: /
    username: guest
    password: guest
    publisher-confirms: true #如果对异步消息需要回调必须设置为true

# 日志配置
logging:
  level:
    org.springframework.data.mongodb.core: debug
    com.macro.mall.mapper: debug
    com.macro.mall.portal.dao: debug
```

### rabbitmq

http://localhost:15672/#/users/guest    默认的位置

```java
rabbitmq:
  host: localhost
  port: 5672
  virtual-host: /
  username: guest
  password: guest
  publisher-confirms: true #如果对异步消息需要回调必须设置为true
```

## application-prod

```java
server:
  port: 8085

spring:
  datasource:
    url: jdbc:mysql://db:3306/mall?useUnicode=true&characterEncoding=utf-8&serverTimezone=Asia/Shanghai
    username: reader
    password: 123456
    druid:
      initial-size: 5 #连接池初始化大小
      min-idle: 10 #最小空闲连接数
      max-active: 20 #最大连接数
      web-stat-filter:
        exclusions: "*.js,*.gif,*.jpg,*.png,*.css,*.ico,/druid/*" #不统计这些请求数据
      stat-view-servlet: #访问监控网页的登录用户名和密码
        login-username: druid
        login-password: druid

  data:
    mongodb:
      host: mongo
      port: 27017
      database: mall-port

  redis:
    host: redis # Redis服务器地址
    database: 0 # Redis数据库索引（默认为0）
    port: 6379 # Redis服务器连接端口
    password: # Redis服务器连接密码（默认为空）
    timeout: 300ms # 连接超时时间（毫秒）

  rabbitmq:
    host: rabbit
    port: 5672
    virtual-host: /mall
    username: mall
    password: mall
    publisher-confirms: true #如果对异步消息需要回调必须设置为true
# 日志配置
logging:
  path: /var/logs
```

### rabbitmq配置

```
rabbitmq:
  host: rabbit
  port: 15672
  virtual-host: /mall
  username: admin
  password: admin
  publisher-confirms: true #如果对异步消息需要回调必须设置为true
```