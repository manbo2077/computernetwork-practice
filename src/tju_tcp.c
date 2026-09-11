#include "tju_tcp.h"
#include <stdarg.h>
#include <time.h>
#include <errno.h>

static FILE* trace_file = NULL;
static pthread_once_t trace_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t trace_lock = PTHREAD_MUTEX_INITIALIZER;

static void trace_init_once(void){
    char hostname[64] = {0};
    const char* path = NULL;

    gethostname(hostname, sizeof(hostname) - 1);

    if(strcmp(hostname, "client") == 0){
        path = "/vagrant/tju_tcp/test/client.event.trace";
    }else if(strcmp(hostname, "server") == 0){
        path = "/vagrant/tju_tcp/test/server.event.trace";
    }else{
        fprintf(stderr, "unknown hostname: %s\n", hostname);
        return;
    }

    trace_file = fopen(path, "w");
    if(trace_file == NULL){
        perror("fopen trace");
        return;
    }

    setvbuf(trace_file, NULL, _IOLBF, 0);
}

static void trace_event(const char* event, const char* format, ...){
    struct timeval now;
    va_list args;

    pthread_once(&trace_once, trace_init_once);
    if(trace_file == NULL){
        return;
    }

    pthread_mutex_lock(&trace_lock);

    gettimeofday(&now, NULL);

    long long timestamp = now.tv_sec* 1000000LL + now.tv_usec;
    fprintf(trace_file, 
            "[%lld] [%s] [",
            timestamp,
            event);

    va_start(args, format);
    vfprintf(trace_file, format, args);
    va_end(args);
    
    fprintf(trace_file, "]\n");

    pthread_mutex_unlock(&trace_lock);
}

static void trace_rwnd(uint32_t size){
    trace_event("RWND", "size:%u", size);
}
static void trace_swnd(uint32_t size){
    trace_event("SWND", "size:%u", size);
}


static void trace_rtts(double sample,
                       double estimated,
                       double deviation,
                       double timeout){
    trace_event("RTTS", 
                "SampleRTT:%f EstimatedRTT:%f "
                "DeviationRTT:%f TimeoutInterval:%f",
                sample, estimated, deviation, timeout
    );
}

static void trace_delv(uint32_t seq, uint32_t size){
    trace_event("DELV", "seq:%u size:%u", seq, size);
}

static void trace_packet_event(const char* event,
                               const char* pkt){
    uint16_t hlen = get_hlen((char*)pkt);
    uint16_t plen = get_plen((char*)pkt);

    uint16_t payload_len = 0;
    if(plen >= hlen){
        payload_len = plen - hlen;
    }

    trace_event(event,
                "seq:%u ack:%u flag:%u length:%u",
                 get_seq((char*)pkt),
                 get_ack((char*)pkt), 
                 get_flags((char*)pkt), 
                 payload_len
    );
}

static void trace_send_packet(char* pkt,
                              int packet_len){
    if(packet_len > MAX_LEN){
        return;
    }
    sendToLayer3(pkt, packet_len);
    trace_packet_event("SEND", pkt);
}


static uint32_t next_isn(void){
    static pthread_mutex_t isn_lock = PTHREAD_MUTEX_INITIALIZER;
    static uint32_t counter = 0;
    
    struct timeval now;
    uint32_t result = 0;

    gettimeofday(&now, NULL);

    pthread_mutex_lock(&isn_lock);

    result = (uint32_t)(
        now.tv_sec * 250000u +
        now.tv_usec/4u +
        counter++);
    
    pthread_mutex_unlock(&isn_lock);

    return result;
}

static void send_control_packet(tju_tcp_t* sock, uint8_t flags, uint32_t seq, uint32_t ack){
    char* pkt;


    pkt = create_packet_buf(
        sock->established_local_addr.port, 
        sock->established_remote_addr.port, 
        seq, 
        ack, 
        DEFAULT_HEADER_LEN, 
        DEFAULT_HEADER_LEN, 
        flags, 
        0, 
        0, 
        NULL, 
        0
    );
    trace_send_packet(pkt, DEFAULT_HEADER_LEN);
    free(pkt);

}

//计算超时的实际时间
static void make_deadline(struct timespec* deadline,
                          unsigned int timeout_ms){
    clock_gettime(CLOCK_REALTIME, deadline);

    deadline->tv_sec += timeout_ms / 1000;
    deadline->tv_nsec +=
        (long)(timeout_ms % 1000) * 1000000L;

    if(deadline->tv_nsec >= 1000000000L){
        deadline->tv_sec += 1;
        deadline->tv_nsec -= 1000000000L;
    }
}

//服务器端握手定时器
static void* server_handshake_timer(void* arg){
    tju_tcp_t* sock = (tju_tcp_t*)arg;

    for(;;){
        struct timespec deadline;
        int wait_result;
        uint32_t seq;
        uint32_t ack;

        pthread_mutex_lock(&sock->state_lock);

        if(sock->state != SYN_RECV ||
           sock->handshake_stop){
            pthread_mutex_unlock(&sock->state_lock);
            return NULL;
        }

        make_deadline(
            &deadline,
            sock->handshake_rto_ms
        );

        wait_result = pthread_cond_timedwait(
            &sock->state_cond,
            &sock->state_lock,
            &deadline
        );

        if(sock->state != SYN_RECV ||
           sock->handshake_stop){
            pthread_mutex_unlock(&sock->state_lock);
            return NULL;
        }

        if(wait_result == ETIMEDOUT){
            if(sock->handshake_retries >=
               HANDSHAKE_MAX_RETRIES){
                sock->state = CLOSED;
                sock->handshake_stop = 1;

                pthread_cond_broadcast(
                    &sock->state_cond
                );

                pthread_mutex_unlock(&sock->state_lock);

                int hashval = cal_hash(
                    sock->established_local_addr.ip,
                    sock->established_local_addr.port,
                    sock->established_remote_addr.ip,
                    sock->established_remote_addr.port
                );

                if(established_socks[hashval] == sock){
                    established_socks[hashval] = NULL;
                }

                return NULL;
            }

            sock->handshake_retries++;
            sock->handshake_retransmitted = 1;

            seq = sock->iss;
            ack = sock->rcv_nxt;

            if(sock->handshake_rto_ms <
               HANDSHAKE_MAX_RTO_MS / 2){
                sock->handshake_rto_ms *= 2;
            }else{
                sock->handshake_rto_ms =
                    HANDSHAKE_MAX_RTO_MS;
            }

            pthread_mutex_unlock(&sock->state_lock);

            send_control_packet(
                sock,
                SYN_FLAG_MASK | ACK_FLAG_MASK,
                seq,
                ack
            );
        }else{
            pthread_mutex_unlock(&sock->state_lock);
        }
    }
}

/*
创建 TCP socket 
初始化对应的结构体
设置初始状态为 CLOSED
*/
tju_tcp_t* tju_socket(){
    tju_tcp_t* sock = (tju_tcp_t*)malloc(sizeof(tju_tcp_t));
    pthread_once(&trace_once, trace_init_once);// 初始化trace文件

    sock->state = CLOSED;
    sock->iss = 0;
    sock->snd_una = 0;
    sock->snd_nxt = 0;
    sock->irs = 0;
    sock->rcv_nxt = 0;

    pthread_mutex_init(&(sock->state_lock), NULL);
    pthread_cond_init(&(sock->state_cond), NULL);

    pthread_mutex_init(&(sock->accept_lock), NULL);
    pthread_cond_init(&(sock->accept_cond), NULL);

	sock->accept_head = NULL;
	sock->accept_tail = NULL;
	sock->accept_next = NULL;
    sock->listen_parent = NULL;
    
    pthread_mutex_init(&(sock->send_lock), NULL);
    sock->sending_buf = NULL;
    sock->sending_len = 0;

    pthread_mutex_init(&(sock->recv_lock), NULL);
    sock->received_buf = NULL;
    sock->received_len = 0;
    
    if(pthread_cond_init(&sock->wait_cond, NULL) != 0){
        perror("ERROR condition variable not set\n");
        exit(-1);
    }

    sock->window.wnd_send = NULL;
    sock->window.wnd_recv = NULL;

    sock->handshake_rto_ms = HANDSHAKE_INITIAL_RTO_MS;
    sock->handshake_retries = 0;
    sock->handshake_stop = 0;
    sock->handshake_retransmitted = 0;

    return sock;
}

/*
绑定监听的地址 包括ip和端口
*/
int tju_bind(tju_tcp_t* sock, tju_sock_addr bind_addr){
    sock->bind_addr = bind_addr;
    return 0;
}

/*
被动打开 监听bind的地址和端口
设置socket的状态为LISTEN
注册该socket到内核的监听socket哈希表
*/
int tju_listen(tju_tcp_t* sock){
    sock->state = LISTEN;
    int hashval = cal_hash(sock->bind_addr.ip, sock->bind_addr.port, 0, 0);
    listen_socks[hashval] = sock;
    return 0;
}

/*
接受连接 
返回与客户端通信用的socket
这里返回的socket一定是已经完成3次握手建立了连接的socket
因为只要该函数返回, 用户就可以马上使用该socket进行send和recv
*/
tju_tcp_t* tju_accept(tju_tcp_t* listen_sock){
    tju_tcp_t* new_conn;

    pthread_mutex_lock(&listen_sock->accept_lock);

    while(listen_sock->accept_head == NULL){
        pthread_cond_wait(
            &listen_sock->accept_cond,
            &listen_sock->accept_lock
        );
    }

    new_conn = listen_sock->accept_head;
    listen_sock->accept_head = new_conn->accept_next;

    if(listen_sock->accept_head == NULL){
        listen_sock->accept_tail = NULL;
    }

    new_conn->accept_next = NULL;

    pthread_mutex_unlock(&listen_sock->accept_lock);

    return new_conn;
}


/*
连接到服务端
该函数以一个socket为参数
调用函数前, 该socket还未建立连接
函数正常返回后, 该socket一定是已经完成了3次握手, 建立了连接
因为只要该函数返回, 用户就可以马上使用该socket进行send和recv
*/
int tju_connect(tju_tcp_t* sock, tju_sock_addr target_addr){

    sock->established_remote_addr = target_addr;

    tju_sock_addr local_addr;
    local_addr.ip = inet_network("172.17.0.2");
    local_addr.port = 5678; // 连接方进行connect连接的时候 内核中是随机分配一个可用的端口
    sock->established_local_addr = local_addr;

    pthread_mutex_lock(&(sock->state_lock));//第一次握手

    sock->iss = next_isn();
    sock->snd_una = sock->iss;
    sock->snd_nxt = sock->iss + 1;
    sock->state = SYN_SENT;

    pthread_mutex_unlock(&(sock->state_lock));
    
    int hashval = cal_hash(local_addr.ip, local_addr.port, target_addr.ip, target_addr.port);//收入已连接的hash表
    established_socks[hashval] = sock;
    send_control_packet(sock, SYN_FLAG_MASK, sock->iss, 0);

    // pthread_mutex_lock(&(sock->state_lock));
    // while(sock->state == SYN_SENT){
    //     pthread_cond_wait(
    //         &(sock->state_cond), 
    //         &(sock->state_lock)
    //     );
    // }

    // int result = sock->state == ESTABLISHED ? 0 : -1;
    // pthread_mutex_unlock(&(sock->state_lock));

    // return result;
    int retries = 0;
    for(;;){
        struct timespec deadline;
        int wait_result;

        pthread_mutex_lock(&(sock->state_lock));
        if(sock->state != SYN_SENT){
            int result = sock->state == ESTABLISHED ? 0 : -1;

            pthread_mutex_unlock(&(sock->state_lock));
            return result;
        }
        
        make_deadline(&deadline, sock->handshake_rto_ms);

        wait_result = pthread_cond_timedwait(
            &(sock->state_cond),
            &(sock->state_lock),
            &deadline
        );

        if(sock->state != SYN_SENT){
            int result = sock->state == ESTABLISHED ? 0 : -1;

            pthread_mutex_unlock(&(sock->state_lock));
            return result;
        }
        if(wait_result == ETIMEDOUT){
            if(retries >= HANDSHAKE_MAX_RETRIES){
                sock->state = CLOSED;
                sock->handshake_stop = 1;
                pthread_cond_broadcast(&(sock->state_cond));

                pthread_mutex_unlock(&(sock->state_lock));

                if(established_socks[hashval] == sock){
                    established_socks[hashval] = NULL;
                }
                return -1;
            }
            retries++;
            sock->handshake_retries = retries;
            sock->handshake_retransmitted = 1;

            if(sock->handshake_rto_ms < HANDSHAKE_MAX_RTO_MS / 2){
                sock->handshake_rto_ms *= 2;
            }else{
                sock->handshake_rto_ms = HANDSHAKE_MAX_RTO_MS;
            }

            pthread_mutex_unlock(&(sock->state_lock));
            send_control_packet(sock, SYN_FLAG_MASK, sock->iss, 0);
        }else if(wait_result != 0){
            sock->state = CLOSED;
            sock->handshake_stop = 1;

            pthread_cond_broadcast(&(sock->state_cond));
            pthread_mutex_unlock(&(sock->state_lock));

            if(established_socks[hashval] == sock){
                established_socks[hashval] = NULL;
            }
            return -1;
        }
        else{
            pthread_mutex_unlock(&(sock->state_lock));
        }

    }
    // 这里也不能直接建立连接 需要经过三次握手
    // 实际在linux中 connect调用后 会进入一个while循环
    // 循环跳出的条件是socket的状态变为ESTABLISHED 表面看上去就是 正在连接中 阻塞
    // 而状态的改变在别的地方进行 在我们这就是tju_handle_packet
    // 将建立了连接的socket放入内核 已建立连接哈希表中
}

int tju_send(tju_tcp_t* sock, const void *buffer, int len){
    // 这里当然不能直接简单地调用sendToLayer3
    char* data = malloc(len);
    memcpy(data, buffer, len);

    char* msg;
    uint32_t seq = 464;
    uint16_t plen = DEFAULT_HEADER_LEN + len;

    msg = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq, 0, 
              DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0, data, len);

    trace_send_packet(msg, plen);
    
    return 0;
}
int tju_recv(tju_tcp_t* sock, void *buffer, int len){
    while(sock->received_len<=0){
        // 阻塞
    }

    while(pthread_mutex_lock(&(sock->recv_lock)) != 0); // 加锁

    int read_len = 0;
    if (sock->received_len >= len){ // 从中读取len长度的数据
        read_len = len;
    }else{
        read_len = sock->received_len; // 读取sock->received_len长度的数据(全读出来)
    }

    memcpy(buffer, sock->received_buf, read_len);

    if(read_len < sock->received_len) { // 还剩下一些
        char* new_buf = malloc(sock->received_len - read_len);
        memcpy(new_buf, sock->received_buf + read_len, sock->received_len - read_len);
        free(sock->received_buf);
        sock->received_len -= read_len;
        sock->received_buf = new_buf;
    }else{
        free(sock->received_buf);
        sock->received_buf = NULL;
        sock->received_len = 0;
    }
    pthread_mutex_unlock(&(sock->recv_lock)); // 解锁

    return 0;
}

int tju_handle_packet(tju_tcp_t* sock, char* pkt){

    trace_packet_event("RECV", pkt);
    uint8_t flags = get_flags(pkt);
    uint32_t seq = get_seq(pkt);
    uint32_t ack = get_ack(pkt);
    pthread_mutex_lock(&sock->state_lock);

    if(sock->state == SYN_RECV &&
        (flags & SYN_FLAG_MASK) != 0 &&
        seq == sock->irs){

        uint32_t synack_seq = sock->iss;
        uint32_t synack_ack = sock->rcv_nxt;

        pthread_mutex_unlock(&sock->state_lock);

        send_control_packet(
            sock,
            SYN_FLAG_MASK | ACK_FLAG_MASK,
            synack_seq,
            synack_ack
        );

        return 0;
    }

    pthread_mutex_unlock(&sock->state_lock);

    //client端三次握手的第二次握手
    pthread_mutex_lock(&(sock->state_lock));
    if(sock->state == SYN_SENT &&
       (flags & (SYN_FLAG_MASK | ACK_FLAG_MASK)) == (SYN_FLAG_MASK | ACK_FLAG_MASK) &&
       ack == sock->snd_nxt){

        sock->irs = seq;
        sock->rcv_nxt = seq + 1;

        sock->snd_una = ack;
        sock->state = ESTABLISHED;

        send_control_packet(sock, ACK_FLAG_MASK, sock->snd_nxt, sock->rcv_nxt);
        pthread_cond_signal(&(sock->state_cond));
        pthread_mutex_unlock(&(sock->state_lock));

        return 0;
    }
    pthread_mutex_unlock(&(sock->state_lock));

    /*
     * 客户端已经建立连接后，
     * 收到服务器重传的 SYN|ACK。
     * 说明之前发送的最终 ACK 可能丢失，
     * 因此需要再次发送 ACK。
     */
    pthread_mutex_lock(&(sock->state_lock));
    if(sock->state == ESTABLISHED &&
       (flags & (SYN_FLAG_MASK | ACK_FLAG_MASK)) ==
           (SYN_FLAG_MASK | ACK_FLAG_MASK) &&
       ack == sock->snd_nxt &&
       seq == sock->irs){

        uint32_t final_ack_seq = sock->snd_nxt;
        uint32_t final_ack_ack = sock->rcv_nxt;

        pthread_mutex_unlock(&(sock->state_lock));

        send_control_packet(
            sock,
            ACK_FLAG_MASK,
            final_ack_seq,
            final_ack_ack
        );

        return 0;
    }
    pthread_mutex_unlock(&(sock->state_lock));

    //服务器端的第一次握手
    pthread_mutex_lock(&(sock->state_lock));

    if(sock->state == LISTEN &&
       (flags & SYN_FLAG_MASK) != 0){

        tju_tcp_t* child = tju_socket();

        /*
         * 先完整初始化 child，
         * 然后才能启动定时器和发送 SYN|ACK。
         */
        child->bind_addr = sock->bind_addr;
        child->established_local_addr = sock->bind_addr;

        child->established_remote_addr.ip =
            inet_network("172.17.0.2");
        child->established_remote_addr.port =
            get_src(pkt);

        child->irs = seq;
        child->rcv_nxt = seq + 1;

        child->iss = next_isn();
        child->snd_una = child->iss;
        child->snd_nxt = child->iss + 1;

        child->listen_parent = sock;
        child->state = SYN_RECV;

        child->handshake_rto_ms = HANDSHAKE_INITIAL_RTO_MS;
        child->handshake_retries = 0;
        child->handshake_stop = 0;
        child->handshake_retransmitted = 0;

        /*
         * 加入已建立连接哈希表，
         * 后续客户端 ACK 才能找到这个 child。
         */
        int hashval = cal_hash(
            child->established_local_addr.ip,
            child->established_local_addr.port,
            child->established_remote_addr.ip,
            child->established_remote_addr.port
        );

        established_socks[hashval] = child;

        /*
         * child 已经是 SYN_RECV，
         * 所以现在启动 SYN|ACK 重传定时器。
         */
        pthread_t timer_thread;

        if(pthread_create(
                &timer_thread,
                NULL,
                server_handshake_timer,
                child
            ) != 0){

            fprintf(stderr,
                    "failed to create handshake timer\n");

            if(established_socks[hashval] == child){
                established_socks[hashval] = NULL;
            }

            child->state = CLOSED;
            child->handshake_stop = 1;

            pthread_mutex_unlock(&(sock->state_lock));
            return -1;
        }

        pthread_detach(timer_thread);

        /*
         * 不要持有监听 socket 的锁发送报文。
         */
        pthread_mutex_unlock(&(sock->state_lock));

        /*
         * 发送服务器的 SYN|ACK。
         */
        send_control_packet(
            child,
            SYN_FLAG_MASK | ACK_FLAG_MASK,
            child->iss,
            child->rcv_nxt
        );

        return 0;
    }
    pthread_mutex_unlock(&(sock->state_lock));

    //服务器端的第三次握手
    pthread_mutex_lock(&(sock->state_lock));
    if(sock->state == SYN_RECV && 
        (flags & ACK_FLAG_MASK ) != 0 && 
        ack == sock->snd_nxt &&
        seq == sock->rcv_nxt){
            sock->snd_una = ack;
            sock->state = ESTABLISHED;

            /*
             * 三次握手完成，通知服务器握手定时器退出。
             */
            sock->handshake_stop = 1;
            pthread_cond_broadcast(&(sock->state_cond));

            pthread_mutex_unlock(&(sock->state_lock));

            tju_tcp_t* parent = sock->listen_parent;
            pthread_mutex_lock(&(parent->accept_lock));
            sock->accept_next = NULL;
            if(parent->accept_tail == NULL){
                parent->accept_head = sock;
                parent->accept_tail = sock;
            } else {
                parent->accept_tail->accept_next = sock;
                parent->accept_tail = sock;
            }

            pthread_cond_signal(&(parent->accept_cond));
            pthread_mutex_unlock(&(parent->accept_lock));

            return 0;
    }
    pthread_mutex_unlock(&(sock->state_lock));

    if(get_plen(pkt) - DEFAULT_HEADER_LEN <= 0){
        return 0;
    }
    if(sock->state != ESTABLISHED){
        return 0;
    }

    uint32_t data_len = get_plen(pkt) - DEFAULT_HEADER_LEN;

    // 把收到的数据放到接受缓冲区
    while(pthread_mutex_lock(&(sock->recv_lock)) != 0); // 加锁

    if(sock->received_buf == NULL){
        sock->received_buf = malloc(data_len);
    }else {
        sock->received_buf = realloc(sock->received_buf, sock->received_len + data_len);
    }
    memcpy(sock->received_buf + sock->received_len, pkt + DEFAULT_HEADER_LEN, data_len);
    sock->received_len += data_len;

    pthread_mutex_unlock(&(sock->recv_lock)); // 解锁


    return 0;
}

int tju_close (tju_tcp_t* sock){
    return 0;
}