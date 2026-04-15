# Makefile for Keyboard Protector Project

# 컴파일러 및 플래그
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -Iinclude -DWIN32_LEAN_AND_MEAN
CFLAGS += -m32
# Windows XP 호환성을 위한 최소 요구사항 정의
CFLAGS += -D_WIN32_WINNT=0x0501
LDFLAGS = -m32 -luser32 -ladvapi32 -lpsapi -lshlwapi

# 디렉토리
SRCDIR = src
INCDIR = include
OBJDIR = obj
BINDIR = bin

# 소스 파일들
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

# 실행 파일 이름
TARGET = $(BINDIR)/keyboard_protector.exe

# 기본 타겟
all: $(TARGET)
	@chcp 65001 >nul
	@echo "빌드 완료"

# 실행 파일 빌드
$(TARGET): $(OBJECTS) | $(BINDIR)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)
	@chcp 65001 >nul
	@echo "빌드 완료: $(TARGET)"

# 오브젝트 파일 빌드
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# 디렉토리 생성
$(OBJDIR):
	mkdir $(OBJDIR)

$(BINDIR):
	mkdir $(BINDIR)

# 정리
clean:
	@if exist $(OBJDIR) rmdir /s /q $(OBJDIR)
	@if exist $(BINDIR) rmdir /s /q $(BINDIR)
	@chcp 65001 >nul
	@echo "정리 완료"

# 다시 빌드
rebuild: clean all

# 실행
run: $(TARGET)
	$(TARGET)

# 디버그 빌드
debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)

# 릴리스 빌드
release: CFLAGS += -O2 -DNDEBUG
release: $(TARGET)

# 도움말
help:
	@chcp 65001 >nul
	@echo "사용 가능한 명령어:"
	@echo "  make          - 빌드 (32비트, 모든 Windows 호환)"
	@echo "  make clean    - 빌드 파일 정리"
	@echo "  make rebuild  - 정리 후 다시 빌드"
	@echo "  make run      - 빌드 후 실행"
	@echo "  make debug    - 디버그 모드로 빌드"
	@echo "  make release  - 릴리스 모드로 빌드"
	@echo "  make help     - 이 도움말 표시"

.PHONY: all clean rebuild run debug release help
