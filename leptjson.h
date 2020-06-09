#ifndef LEPTJSON_H__
#define LEPTJSON_H__

#include <stddef.h> /* size_t */

typedef enum{//枚举JSON的类型
    LEPT_NULL, LEPT_FALSE, LEPT_TRUE, LEPT_NUMBER, LEPT_STRING, LEPT_ARRAY, LEPT_OBJECT
} lept_type;

typedef struct lept_value lept_value;
struct lept_value{//JSON数据结构
    union {
        struct { lept_value* e; size_t size; }a;    /* array:  elements, element count */
        struct { char* s; size_t len; }s;           /* string: null-terminated string, string length */
        double n;                                   /* number */
    }u;
    lept_type type;
};

enum{  //返回值
    LEPT_PARSE_OK = 0,
    LEPT_PARSE_EXPECT_VALUE,//空白
    LEPT_PARSE_INVALID_VALUE,//无效字符
    LEPT_PARSE_ROOT_NOT_SINGULAR,//值/空白后还有字符
    LEPT_PARSE_NUMBER_TOO_BIG,//INF
    LEPT_PARSE_MISS_QUOTATION_MARK,
    LEPT_PARSE_INVALID_STRING_ESCAPE,
    LEPT_PARSE_INVALID_STRING_CHAR,
    LEPT_PARSE_INVALID_UNICODE_HEX,
    LEPT_PARSE_INVALID_UNICODE_SURROGATE,
    LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET
};

int lept_parse(lept_value* v, const char* json);//解析JSON

lept_type lept_get_type(const lept_value* v);//获取类型

#define lept_init(v) do { (v)->type = LEPT_NULL; } while(0)

void lept_free(lept_value* v);

#define lept_set_null(v) lept_free(v)

int lept_get_boolean(const lept_value* v);
void lept_set_boolean(lept_value* v, int b);

double lept_get_number(const lept_value* v);
void lept_set_number(lept_value* v, double n);

const char* lept_get_string(const lept_value* v);
size_t lept_get_string_length(const lept_value* v);
void lept_set_string(lept_value* v, const char* s, size_t len);

size_t lept_get_array_size(const lept_value* v);
lept_value* lept_get_array_element(const lept_value* v, size_t index);

#endif /*LEPTJSON_H__*/