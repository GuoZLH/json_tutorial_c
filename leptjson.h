#ifndef LEPTJSON_H__
#define LEPTJSON_H__

typedef enum{//枚举JSON的类型
    LEPT_NULL, LEPT_FALSE, LEPT_TRUE, LEPT_NUMBER, LEPT_STRING, LEPT_ARRAY, LEPT_OBJECT
} lept_type;

typedef struct{//JSON数据结构
    lept_type type;
}lept_value;

enum{  //返回值
    LEPT_PARSE_OK = 0,
    LEPT_PARSE_EXPECT_VALUE,//空白
    LEPT_PARSE_INVALID_VALUE,//无效字符
    LEPT_PARSE_ROOT_NOT_SINGULAR//值/空白后还有字符
};

int lept_parse(lept_value* v, const char* json);//解析JSON

lept_type lept_get_type(const lept_value* v);//获取类型

#endif /*LEPTJSON_H__*/