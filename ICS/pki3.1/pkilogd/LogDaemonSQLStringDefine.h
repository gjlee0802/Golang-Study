#ifndef _LOG_DAEMON_SQL_STRING_DEFINE_H
#define _LOG_DAEMON_SQL_STRING_DEFINE_H

#define LOG_DAEMON_SQL_FORMAT_SELECT_CFG_COUNT \
          "SELECT COUNT(*) FROM LOG_CFG WHERE LOG_FILENAME = '%s'"

#define LOG_DAEMON_SQL_FORMAT_INSERT_CFG \
          "INSERT INTO LOG_CFG (LOG_GROUP, LOG_SYSTEM, LOG_IP, " \
          "LOG_PROCESS, LOG_TYPE, LOG_NAME, LOG_FILEDESC, LOG_FILENAME, " \
          "LOG_TABLE, LOG_FILE_VALID_TIME, LOG_RECOVERY) " \
          "VALUES ('%s', '%s', '%s', '%s', %d, '%s', '%s', '%s', '%s', %d, %d)"

#define LOG_DAEMON_SQL_FORMAT_SELECT_MAX_SIZE \
          "SELECT MAX(LOG_SIZE) FROM %s WHERE LOG_SYSTEM='%s' AND " \
          "LOG_PROCESS='%s' AND LOG_IP='%s' AND LOG_NAME='%s' " \
          "AND LOG_TIME >= TO_DATE('%s 000000','%s HH24MISS') AND " \
          "LOG_TIME <= TO_DATE('%s 235959','%s HH24MISS')"

// 아래의 insert statement는 로그 파일의 순서와 거의 일치하지만
// 다음 두가지의 예외가 있다.
// 1. LOG_SIZE는 파일에서 로그 한 줄을 읽은 후의 tellg의 결과 값이다.
// 2. LOG_NAME은 해당 파일에 대해 LOG_CFG에 존재하는 LOG_NAME 값이다.
#define LOG_DAEMON_SQL_FORMAT_INSERT_LOG \
          "INSERT INTO PKI_SLOG (" \
          "LOG_GROUP, LOG_SYSTEM, LOG_IP, LOG_PROCESS, LOG_TYPE, " \
          "LOG_NAME, LOG_TIME, LOG_SIZE, LOG_CODE, LOG_SEVERITY, " \
          "LOG_CATEGORY, LOG_DES, LOG_OPT, REQ_IP, REQ_DN, " \
          "REQ_ID, REQ_TYPE, SUBJECT_DN, SUBJECT_ID) " \
          "VALUES (" \
          "'%s', '%s', '%s', '%s', %d, " \
          "'%s', TO_DATE('%s', 'YYYY/MM/DD HH24:MI:SS'), %d, %d, '%s', " \
          "'%s', '%s', '%s', '%s', '%s', " \
          "'%s', '%s', '%s', '%s')"

#endif

