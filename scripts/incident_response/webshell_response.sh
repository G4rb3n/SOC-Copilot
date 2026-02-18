#!/bin/bash
###############################################################################
# Webshell上传攻击响应处置脚本
#
# 功能：
# 1. 删除上传的webshell文件
# 2. 封禁攻击者IP
# 3. 检查webshell是否被执行（创建进程、修改文件等）
# 4. 临时加固上传接口
# 5. 收集取证信息
#
# 使用方法：
#   sudo ./webshell_response.sh [--victim-ip IP] [--webshell-path PATH] [--attacker-ip IP]
#
# 注意：
#   - 需要root权限执行
#   - 建议在处置前备份关键数据
#   - 执行前请确认参数正确
###############################################################################

set -e

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

# 默认参数
VICTIM_IP="${VICTIM_IP:-2.15.16.44}"
WEBSHELL_PATH="${WEBSHELL_PATH:-/tmp/join/shell.jsp}"
ATTACKER_IP="${ATTACKER_IP:-59.56.48.110}"
BACKUP_DIR="/tmp/webshell_response_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="/var/log/webshell_response_$(date +%Y%m%d_%H%M%S).log"

# 创建备份目录
mkdir -p "$BACKUP_DIR"

# 记录日志
exec > >(tee -a "$LOG_FILE") 2>&1

log_info "=========================================="
log_info "Webshell上传攻击响应处置脚本"
log_info "=========================================="
log_info "受害主机: $VICTIM_IP"
log_info "Webshell路径: $WEBSHELL_PATH"
log_info "攻击者IP: $ATTACKER_IP"
log_info "备份目录: $BACKUP_DIR"
log_info "=========================================="

###############################################################################
# 1. 检查权限和环境
###############################################################################
check_prerequisites() {
    log_info "[1] 检查权限和环境..."

    # 检查root权限
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要root权限执行"
        exit 1
    fi

    # 检测操作系统类型
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
        log_info "操作系统: $OS $VERSION"
    else
        log_warn "无法检测操作系统类型"
    fi

    log_info "权限检查完成"
}

###############################################################################
# 2. 收集取证信息
###############################################################################
collect_forensics() {
    log_info "[2] 收集取证信息..."

    # 收集网络连接信息
    log_info "收集网络连接状态..."
    netstat -tuln > "$BACKUP_DIR/netstat.txt" 2>/dev/null || ss -tuln > "$BACKUP_DIR/netstat.txt" 2>/dev/null
    netstat -tunap > "$BACKUP_DIR/netstat_processes.txt" 2>/dev/null || ss -tunap > "$BACKUP_DIR/netstat_processes.txt" 2>/dev/null

    # 收集进程信息
    log_info "收集进程信息..."
    ps auxf > "$BACKUP_DIR/ps.txt"
    ps auxef > "$BACKDIR/ps_ef.txt"

    # 收集最近登录信息
    log_info "收集登录信息..."
    last > "$BACKUP_DIR/last.txt" 2>/dev/null || true
    who > "$BACKUP_DIR/who.txt" 2>/dev/null || true
    w > "$BACKUP_DIR/w.txt" 2>/dev/null || true

    # 收集webshell文件信息（如果存在）
    if [ -f "$WEBSHELL_PATH" ]; then
        log_info "收集webshell文件信息..."
        ls -la "$WEBSHELL_PATH" > "$BACKUP_DIR/webshell_fileinfo.txt"
        stat "$WEBSHELL_PATH" > "$BACKUP_DIR/webshell_stat.txt"
        md5sum "$WEBSHELL_PATH" > "$BACKUP_DIR/webshell_md5.txt" 2>/dev/null || true
        sha256sum "$WEBSHELL_PATH" > "$BACKUP_DIR/webshell_sha256.txt" 2>/dev/null || true
        cp "$WEBSHELL_PATH" "$BACKUP_DIR/webshell_backup.jsp" 2>/dev/null || true
    fi

    # 收集最近文件变化
    log_info "收集文件系统变化..."
    find /tmp -name "*.jsp" -mtime -1 > "$BACKUP_DIR/recent_jsp_files.txt" 2>/dev/null || true

    log_info "取证信息收集完成，保存在: $BACKUP_DIR"
}

###############################################################################
# 3. 删除webshell文件
###############################################################################
remove_webshell() {
    log_info "[3] 检查并删除webshell文件..."

    if [ ! -f "$WEBSHELL_PATH" ]; then
        log_warn "Webshell文件不存在: $WEBSHELL_PATH"
        log_warn "文件可能已被删除或路径不正确"
        return
    fi

    # 再次确认
    log_warn "即将删除文件: $WEBSHELL_PATH"
    read -p "确认删除？(yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        log_warn "用户取消删除操作"
        return
    fi

    # 删除文件
    rm -f "$WEBSHELL_PATH"
    log_info "Webshell文件已删除: $WEBSHELL_PATH"

    # 检查是否有其他类似的webshell文件
    log_info "检查其他可疑的webshell文件..."
    find /tmp -name "*.jsp" -o -name "*.php" -o -name "*.asp" -o -name "*.aspx" 2>/dev/null | while read file; do
        if [ -f "$file" ]; then
            log_warn "发现可疑文件: $file"
            # 可以根据需要添加文件内容检查逻辑
        fi
    done
}

###############################################################################
# 4. 封禁攻击者IP
###############################################################################
block_attacker_ip() {
    log_info "[4] 封禁攻击者IP: $ATTACKER_IP"

    # 使用iptables封禁（如果可用）
    if command -v iptables &> /dev/null; then
        # 检查规则是否已存在
        if iptables -C INPUT -s "$ATTACKER_IP" -j DROP &> /dev/null; then
            log_warn "IP $ATTACKER_IP 已被封禁"
        else
            iptables -A INPUT -s "$ATTACKER_IP" -j DROP
            log_info "已通过iptables封禁IP: $ATTACKER_IP"

            # 保存iptables规则
            if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
                iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            elif [ "$OS" = "centos" ] || [ "$OS" = "rhel" ]; then
                service iptables save 2>/dev/null || true
            fi
        fi
    else
        log_warn "iptables命令不可用，请手动封禁IP: $ATTACKER_IP"
    fi

    # 记录到hosts.deny（如果使用tcpd）
    if [ -f /etc/hosts.deny ]; then
        if ! grep -q "$ATTACKER_IP" /etc/hosts.deny; then
            echo "ALL: $ATTACKER_IP" >> /etc/hosts.deny
            log_info "已添加到 /etc/hosts.deny: $ATTACKER_IP"
        fi
    fi
}

###############################################################################
# 5. 检查webshell执行痕迹
###############################################################################
check_webshell_execution() {
    log_info "[5] 检查webshell执行痕迹..."

    # 检查是否有异常进程（简单检查）
    log_info "检查是否有可疑进程..."
    # 检查是否有jsp相关的进程
    if ps aux | grep -i jsp | grep -v grep; then
        log_warn "发现JSP相关进程，请手动检查"
    fi

    # 检查是否有shell相关的异常进程
    if ps aux | grep -E '(bash|sh|ksh)' | grep -v grep | awk '{print $11}' | xargs -I {} lsof -p {} 2>/dev/null | grep -q "$WEBSHELL_PATH"; then
        log_warn "发现可能访问webshell的进程"
    fi

    # 检查最近的命令历史（如果有）
    if [ -f ~/.bash_history ]; then
        log_info "保存最近的命令历史..."
        cp ~/.bash_history "$BACKUP_DIR/bash_history.txt" 2>/dev/null || true
    fi
}

###############################################################################
# 6. 临时加固上传接口
###############################################################################
harden_upload_interface() {
    log_info "[6] 临时加固建议..."

    log_warn "建议的加固措施："
    log_warn "1. 限制上传接口的访问权限"
    log_warn "2. 添加文件类型白名单验证"
    log_warn "3. 重命名或禁用上传接口: /uapim/upload/grouptemplet"
    log_warn "4. 检查是否有未授权访问漏洞"
    log_warn "5. 更新相关应用程序和依赖库"

    # 如果是web服务器，可以提供具体的配置建议
    if [ -f /etc/nginx/nginx.conf ]; then
        log_info "检测到Nginx，建议添加以下配置："
        cat << 'EOF'
location ~ /uapim/upload/ {
    # 限制请求方法
    if ($request_method !~ ^(POST)$ ) {
        return 403;
    }
    # 限制文件类型
    if ($request_filename ~* \.(jsp|php|asp|aspx)$) {
        return 403;
    }
}
EOF
    fi

    if [ -f /etc/httpd/conf/httpd.conf ] || [ -f /etc/apache2/apache2.conf ]; then
        log_info "检测到Apache，建议添加以下配置："
        cat << 'EOF'
<Location "/uapim/upload/">
    # 限制请求方法
    <LimitExcept POST>
        Require all denied
    </LimitExcept>
    # 禁止上传脚本文件
    <FilesMatch "\.(jsp|php|asp|aspx)$">
        Require all denied
    </FilesMatch>
</Location>
EOF
    fi
}

###############################################################################
# 7. 生成处置报告
###############################################################################
generate_report() {
    log_info "[7] 生成处置报告..."

    REPORT_FILE="$BACKUP_DIR/response_report.md"

    cat > "$REPORT_FILE" << EOF
# Webshell上传攻击响应处置报告

## 基本信息
| 项目 | 内容 |
|------|------|
| 处置时间 | $(date) |
| 受害主机 | $VICTIM_IP |
| Webshell路径 | $WEBSHELL_PATH |
| 攻击者IP | $ATTACKER_IP |

## 处置措施

### 1. 取证信息收集
- 网络连接状态: $BACKUP_DIR/netstat.txt
- 进程信息: $BACKUP_DIR/ps.txt
- 登录信息: $BACKUP_DIR/last.txt
- Webshell文件信息: $BACKUP_DIR/webshell_*

### 2. Webshell文件处置
- 文件已删除: $WEBSHELL_PATH
- 文件已备份: $BACKUP_DIR/webshell_backup.jsp

### 3. 网络封禁
- 已封禁攻击IP: $ATTACKER_IP

### 4. 后续建议
1. 进行全面的恶意代码扫描
2. 检查是否有其他失陷主机
3. 修复上传接口的漏洞
4. 加强日志监控和告警
5. 进行安全加固和漏洞修复

## 验证检查
- [ ] Webshell文件已删除
- [ ] 攻击者IP已封禁
- [ ] 无可疑进程运行
- [ ] 上传接口已加固

## 附加信息
详细日志: $LOG_FILE
备份目录: $BACKUP_DIR
EOF

    log_info "处置报告已生成: $REPORT_FILE"
}

###############################################################################
# 主函数
###############################################################################
main() {
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            --victim-ip)
                VICTIM_IP="$2"
                shift 2
                ;;
            --webshell-path)
                WEBSHELL_PATH="$2"
                shift 2
                ;;
            --attacker-ip)
                ATTACKER_IP="$2"
                shift 2
                ;;
            *)
                log_error "未知参数: $1"
                exit 1
                ;;
        esac
    done

    # 执行处置流程
    check_prerequisites
    collect_forensics
    remove_webshell
    block_attacker_ip
    check_webshell_execution
    harden_upload_interface
    generate_report

    log_info "=========================================="
    log_info "响应处置完成！"
    log_info "=========================================="
    log_info "备份目录: $BACKUP_DIR"
    log_info "日志文件: $LOG_FILE"
    log_info "=========================================="
}

# 执行主函数
main "$@"
