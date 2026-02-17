#!/bin/bash
###############################################################################
# Webshell上传事件响应脚本
#
# 用途：自动化响应webshell上传事件，包括隔离主机、删除恶意文件、封禁攻击IP等
#
# 使用方法：
#   1. 在失陷主机上直接执行
#   2. 或通过SSH/RDP远程执行: ./webshell_upload_response.sh
#
# 注意：执行前请确认脚本权限 chmod +x webshell_upload_response.sh
###############################################################################

set -e  # 遇到错误立即退出

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查是否为root用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要root权限执行"
        log_info "请使用: sudo $0"
        exit 1
    fi
}

# 备份配置
backup_config() {
    local backup_dir="/tmp/webshell_response_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"

    log_info "备份当前配置到: $backup_dir"

    # 备份iptables规则
    if command -v iptables &> /dev/null; then
        iptables-save > "$backup_dir/iptables.rules" 2>/dev/null || true
    fi

    # 备份文件列表（用于删除前记录）
    echo "$backup_dir"
}

# 封禁攻击IP
block_attacker_ip() {
    local attacker_ip="$1"

    log_info "封禁攻击IP: $attacker_ip"

    # 使用iptables封禁
    if command -v iptables &> /dev/null; then
        # 检查规则是否已存在
        if ! iptables -C INPUT -s "$attacker_ip" -j DROP &>/dev/null; then
            iptables -A INPUT -s "$attacker_ip" -j DROP
            iptables -A OUTPUT -d "$attacker_ip" -j DROP
            log_info "已通过iptables封禁IP: $attacker_ip"
        else
            log_warn "IP $attacker_ip 已被封禁，跳过"
        fi
    else
        log_warn "未找到iptables命令，跳过IP封禁"
    fi

    # 使用hosts.deny封禁（如果适用）
    if [ -f /etc/hosts.deny ]; then
        if ! grep -q "^ALL: $attacker_ip" /etc/hosts.deny; then
            echo "ALL: $attacker_ip" >> /etc/hosts.deny
            log_info "已添加到 /etc/hosts.deny"
        fi
    fi
}

# 恢复IP封禁
unblock_attacker_ip() {
    local attacker_ip="$1"

    log_info "解封IP: $attacker_ip"

    if command -v iptables &> /dev/null; then
        iptables -D INPUT -s "$attacker_ip" -j DROP 2>/dev/null || true
        iptables -D OUTPUT -d "$attacker_ip" -j DROP 2>/dev/null || true
        log_info "已从iptables移除封禁: $attacker_ip"
    fi

    if [ -f /etc/hosts.deny ]; then
        sed -i "/^ALL: $attacker_ip/d" /etc/hosts.dney 2>/dev/null || true
        log_info "已从 /etc/hosts.deny 移除"
    fi
}

# 删除webshell文件
remove_webshell() {
    local webshell_path="$1"

    log_info "删除webshell文件: $webshell_path"

    if [ -f "$webshell_path" ]; then
        # 记录文件信息
        log_info "文件信息:"
        ls -lh "$webshell_path"

        # 删除文件
        rm -f "$webshell_path"
        log_info "已删除: $webshell_path"
    else
        log_warn "文件不存在: $webshell_path"
    fi
}

# 查找其他潜在的webshell
find_other_webshells() {
    log_info "扫描其他潜在webshell文件..."

    # 常见web目录
    local web_dirs=(
        "/var/www/html"
        "/var/www"
        "/usr/share/nginx/html"
        "/home/*/public_html"
        "/tmp"
        "/dev/shm"
        "/tmp/join"
    )

    # 常见webshell文件名模式
    local shell_patterns=(
        "*shell*.php"
        "*shell*.jsp"
        "*shell*.asp"
        "c*.php"
        "cmd*.php"
        "eval*.php"
        "hack*.php"
        "spy*.php"
        "webshell*"
        ".*.php"  # 隐藏文件
    )

    for dir in "${web_dirs[@]}"; do
        if [ -d "$dir" ]; then
            log_info "扫描目录: $dir"

            # 查找最近修改的可疑文件
            find "$dir" -type f \( -name "*.php" -o -name "*.jsp" -o -name "*.asp" -o -name "*.aspx" \) -mtime -7 -ls 2>/dev/null || true

            # 查找包含webshell特征的文件
            log_info "检测webshell特征..."
            grep -r -l "eval(" "$dir" --include="*.php" 2>/dev/null || true
            grep -r -l "base64_decode" "$dir" --include="*.php" 2>/dev/null || true
            grep -r -l "system(" "$dir" --include="*.php" 2>/dev/null || true
            grep -r -l "Runtime.getRuntime" "$dir" --include="*.jsp" 2>/dev/null || true
        fi
    done
}

# 检查异常网络连接
check_network_connections() {
    log_info "检查异常网络连接..."

    # 检查外联连接
    log_info "当前对外网络连接:"
    netstat -antp 2>/dev/null | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort -u | head -20 || true

    # 检查可疑端口监听
    log_info "监听端口:"
    netstat -antlp 2>/dev/null | grep LISTEN || true
}

# 检查异常进程
check_suspicious_processes() {
    log_info "检查异常进程..."

    # 检查可疑进程名
    local suspicious_processes=(
        "nc.*-l"
        "ncat.*-l"
        "bash.*-i"
        "perl.*-e"
        "python.*-c"
        "telnet.*-l"
        "socat"
        "meterpreter"
        "msfvenom"
    )

    for pattern in "${suspicious_processes[@]}"; do
        if ps aux | grep -E "$pattern" | grep -v grep; then
            log_warn "发现可疑进程: $pattern"
        fi
    done
}

# 检查定时任务
check_cron_jobs() {
    log_info "检查定时任务..."

    # 检查系统定时任务
    if [ -f /etc/crontab ]; then
        log_info "/etc/crontab 内容:"
        cat /etc/crontab
    fi

    # 检查用户定时任务
    for cron_dir in /etc/cron.* /var/spool/cron/crontabs; do
        if [ -d "$cron_dir" ]; then
            log_info "检查目录: $cron_dir"
            ls -la "$cron_dir"
        fi
    done
}

# 修复文件上传漏洞建议
fix_upload_vulnerability() {
    log_info "文件上传漏洞修复建议:"
    cat << 'EOF'

1. 限制文件类型：
   - 在上传接口添加文件类型白名单验证
   - 仅允许业务必需的文件类型

2. 文件内容检测：
   - 对上传文件进行内容检查
   - 拒绝包含可执行代码的文件

3. 文件重命名：
   - 上传后重命名文件，避免使用原始文件名
   - 使用UUID或随机字符串命名

4. 存储位置：
   - 将上传文件存储在web目录之外
   - 或禁止上传目录的执行权限

5. 访问控制：
   - 对上传目录禁用执行权限 (chmod -x)
   - 配置web服务器禁止脚本执行

6. 示例配置：

   Nginx配置：
   location /uploads/ {
       location ~ \.(php|jsp|asp|aspx)$ {
           deny all;
       }
   }

   Apache配置：
   <Directory "/var/www/html/uploads">
       <FilesMatch "\.(php|jsp|asp|aspx)$">
           Order Allow,Deny
           Deny from all
       </FilesMatch>
   </Directory>

EOF
}

# 生成监控建议
generate_monitoring_rules() {
    log_info "安全监控建议:"

    cat << 'EOF'

建议添加以下监控规则：

1. 监控web目录文件创建
   - 监控 /var/www/html 下 .php/.jsp/.asp 文件的创建

2. 监控上传接口访问
   - 监控 /upload 接口的异常User-Agent
   - 监控同一IP频繁访问上传接口

3. 监控文件上传行为
   - 监控 POST 请求 Content-Type: multipart/form-data
   - 监控上传脚本类型文件

4. 监控webshell访问
   - 监控对可疑文件名的访问 (shell.*, cmd.*, c.*, etc.)

5. 监控攻击IP
   - 持续监控攻击IP 59.56.48.110 的后续访问

6. 监控外联行为
   - 监控失陷主机对外发起的可疑连接

EOF
}

# 主函数
main() {
    echo "============================================================"
    echo "  Webshell上传事件响应脚本"
    echo "============================================================"
    echo ""

    # 检查root权限
    check_root

    # 备份配置
    backup_dir=$(backup_config)

    # 从参数获取威胁实体信息
    # 或使用交互式输入
    if [ $# -ge 2 ]; then
        ATTACKER_IP="$1"
        WEBSHELL_PATH="$2"
    else
        read -p "请输入攻击IP: " ATTACKER_IP
        read -p "请输入webshell文件路径: " WEBSHELL_PATH
    fi

    log_info "响应处置开始..."
    log_info "攻击IP: $ATTACKER_IP"
    log_info "Webshell路径: $WEBSHELL_PATH"
    echo ""

    # 1. 封禁攻击IP
    block_attacker_ip "$ATTACKER_IP"
    echo ""

    # 2. 删除webshell文件
    remove_webshell "$WEBSHELL_PATH"
    echo ""

    # 3. 查找其他潜在webshell
    find_other_webshells
    echo ""

    # 4. 检查异常网络连接
    check_network_connections
    echo ""

    # 5. 检查异常进程
    check_suspicious_processes
    echo ""

    # 6. 检查定时任务
    check_cron_jobs
    echo ""

    # 7. 漏洞修复建议
    fix_upload_vulnerability
    echo ""

    # 8. 监控建议
    generate_monitoring_rules
    echo ""

    log_info "响应处置完成！"
    log_info "配置备份位置: $backup_dir"

    echo ""
    echo "后续建议："
    echo "  1. 持续监控攻击IP和失陷主机的后续行为"
    echo "  2. 修复文件上传漏洞"
    echo "  3. 加强应用安全防护"
    echo "  4. 进行全面的安全检查"
    echo ""

    # 询问是否保存iptables规则
    read -p "是否保存iptables规则以便重启后生效？(y/n): " save_iptables
    if [ "$save_iptables" = "y" ] || [ "$save_iptables" = "Y" ]; then
        if command -v iptables-save &> /dev/null; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
            iptables-save > /etc/sysconfig/iptables 2>/dev/null || \
            log_warn "无法自动保存iptables规则，请手动保存"
            log_info "iptables规则已保存"
        fi
    fi
}

# 显示帮助信息
show_help() {
    cat << EOF

用法: $0 [攻击IP] [Webshell路径]

参数:
  攻击IP        - 可选，攻击者IP地址，如: 59.56.48.110
  Webshell路径  - 可选，恶意文件路径，如: /tmp/join/shell.jsp

示例:
  $0                                    # 交互式输入
  $0 59.56.48.110 /tmp/join/shell.jsp  # 命令行参数

说明:
  此脚本用于自动化响应webshell上传事件，包括：
  - 封禁攻击者IP
  - 删除webshell文件
  - 扫描其他潜在威胁
  - 检查异常连接和进程
  - 提供修复建议

注意:
  - 脚本需要root权限执行
  - 执行前会自动备份配置
  - 建议在测试环境验证后再用于生产环境

EOF
}

# 参数处理
case "${1:-}" in
    -h|--help|help)
        show_help
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac
