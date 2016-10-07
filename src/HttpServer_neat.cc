/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include "HttpServer_neat.h"

#include <sys/stat.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif // HAVE_SYS_SOCKET_H
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif // HAVE_NETDB_H
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif // HAVE_UNISTD_H
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif // HAVE_FCNTL_H
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif // HAVE_NETINET_IN_H
#include <netinet/tcp.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif // HAVE_ARPA_INET_H

#include <cassert>
#include <set>
#include <iostream>
#include <thread>
#include <mutex>
#include <deque>

#include <zlib.h>
#include <neat/neat.h>
#include "../../neat/neat_internal.h"

#include "app_helper.h"
#include "http2.h"
#include "util.h"
#include "template.h"

#ifndef O_BINARY
#define O_BINARY (0)
#endif // O_BINARY

static const char *config_property = "{\
    \"transport\": [\
        {\
            \"value\": \"SCTP\",\
            \"precedence\": 1\
        },\
        {\
            \"value\": \"TCP\",\
            \"precedence\": 1\
        }\
    ]\
}";\

namespace nghttp2 {

namespace {
// TODO could be constexpr
constexpr auto DEFAULT_HTML = StringRef::from_lit("index.html");
constexpr auto NGHTTPD_SERVER =
    StringRef::from_lit("nghttpd nghttp2/" NGHTTP2_VERSION);
} // namespace

namespace {
void delete_handler(Http2Handler *handler) {
  handler->remove_self();
  delete handler;
}
} // namespace

namespace {
void print_session_id(int64_t id) { std::cout << "[id=" << id << "] "; }
} // namespace

Config::Config()
    : mime_types_file("/etc/mime.types"),
      stream_read_timeout(1_min),
      stream_write_timeout(1_min),
      data_ptr(nullptr),
      padding(0),
      num_worker(1),
      max_concurrent_streams(100),
      header_table_size(-1),
      window_bits(-1),
      connection_window_bits(-1),
      port(0),
      verbose(false),
      daemon(false),
      verify_client(false),
      no_tls(false),
      error_gzip(false),
      early_response(false),
      hexdump(false),
      echo_upload(false),
      no_content_length(false) {}

Config::~Config() {}

namespace {
void stream_timeout_cb(uv_timer_t *w) {
  int rv;
  auto stream = static_cast<Stream *>(w->data);
  auto hd = stream->handler;
  auto config = hd->get_config();

  uv_timer_stop(&stream->rtimer);
  uv_timer_stop(&stream->wtimer);

  if (config->verbose) {
    print_session_id(hd->session_id());
    print_timer();
    std::cout << " timeout stream_id=" << stream->stream_id << std::endl;
  }

  hd->submit_rst_stream(stream, NGHTTP2_INTERNAL_ERROR);

  rv = hd->on_write();
  if (rv == -1) {
    delete_handler(hd);
  }
}
} // namespace

namespace {
void add_stream_read_timeout(Stream *stream) {
  auto hd = stream->handler;
  auto config = hd->get_config();

  if (uv_is_active((uv_handle_t *) &stream->rtimer)) {
    uv_timer_again(&stream->rtimer);
  } else if (config->stream_read_timeout) {
    uv_timer_start(&stream->rtimer, stream_timeout_cb, 0, config->stream_read_timeout);
  }
}
} // namespace

namespace {
void add_stream_read_timeout_if_pending(Stream *stream) {
  if (uv_is_active((uv_handle_t *) &stream->rtimer)) {
    uv_timer_again(&stream->rtimer);
  }
}
} // namespace

namespace {
void add_stream_write_timeout(Stream *stream) {
  auto hd = stream->handler;
  auto config = hd->get_config();

  if (uv_is_active((uv_handle_t *) &stream->wtimer)) {
    uv_timer_again(&stream->wtimer);
  } else if (config->stream_write_timeout) {
    uv_timer_start(&stream->wtimer, stream_timeout_cb, 0, config->stream_write_timeout);
  }
}
} // namespace

namespace {
void remove_stream_read_timeout(Stream *stream) {
  uv_timer_stop(&stream->rtimer);
}
} // namespace

namespace {
void remove_stream_write_timeout(Stream *stream) {
  uv_timer_stop(&stream->wtimer);
}
} // namespace

namespace {
void fill_callback(nghttp2_session_callbacks *callbacks, const Config *config);
} // namespace

namespace {
constexpr uint64_t RELEASE_FD_TIMEOUT = 2000;
} // namespace

namespace {
void release_fd_cb(uv_timer_t *w);
} // namespace

namespace {
constexpr uint64_t FILE_ENTRY_MAX_AGE = 10000;
} // namespace

namespace {
constexpr size_t FILE_ENTRY_EVICT_THRES = 2048;
} // namespace

namespace {
bool need_validation_file_entry(const FileEntry *ent, uint64_t now) {
  return ent->last_valid + FILE_ENTRY_MAX_AGE < now;
}
} // namespace

namespace {
bool validate_file_entry(FileEntry *ent, uint64_t now) {
  struct stat stbuf;
  int rv;

  rv = fstat(ent->fd, &stbuf);
  if (rv != 0) {
    ent->stale = true;
    return false;
  }

  if (stbuf.st_nlink == 0 || ent->mtime != stbuf.st_mtime) {
    ent->stale = true;
    return false;
  }

  ent->mtime = stbuf.st_mtime;
  ent->last_valid = now;

  return true;
}
} // namespace

class Sessions {
public:
  Sessions(HttpServer *sv, uv_loop_t *loop, const Config *config)
      : sv_(sv),
        loop_(loop),
        config_(config),
        callbacks_(nullptr),
        next_session_id_(1),
        tstamp_cached_(uv_now(loop)),
        cached_date_(util::http_date(tstamp_cached_)) {
    nghttp2_session_callbacks_new(&callbacks_);

    fill_callback(callbacks_, config_);

    uv_timer_init(loop, &release_fd_timer_);
    release_fd_timer_.data = this;
  }
  ~Sessions() {
    uv_timer_stop(&release_fd_timer_);
    for (auto handler : handlers_) {
      delete handler;
    }
    nghttp2_session_callbacks_del(callbacks_);
  }
  void add_handler(Http2Handler *handler) { handlers_.insert(handler); }
  void remove_handler(Http2Handler *handler) {
    handlers_.erase(handler);
    if (handlers_.empty() && !fd_cache_.empty()) {
      //ev_timer_again(loop_, &release_fd_timer_);
      if (uv_is_active((uv_handle_t *) &release_fd_timer_)) {
        uv_timer_again(&release_fd_timer_);
      } else {
        uv_timer_start(&release_fd_timer_, release_fd_cb, 0, RELEASE_FD_TIMEOUT);
      }
    }
  }

  const Config *get_config() const { return config_; }
  uv_loop_t *get_loop() const {
    return loop_;
  }
  int64_t get_next_session_id() {
    auto session_id = next_session_id_;
    if (next_session_id_ == std::numeric_limits<int64_t>::max()) {
      next_session_id_ = 1;
    } else {
      ++next_session_id_;
    }
    return session_id;
  }
  const nghttp2_session_callbacks *get_callbacks() const { return callbacks_; }

  void update_cached_date() { cached_date_ = util::http_date(tstamp_cached_); }
  const std::string &get_cached_date() {
    auto t = uv_now(loop_);
    if (t != tstamp_cached_) {
      tstamp_cached_ = t;
      update_cached_date();
    }
    return cached_date_;
  }
  FileEntry *get_cached_fd(const std::string &path) {
    auto range = fd_cache_.equal_range(path);
    if (range.first == range.second) {
      return nullptr;
    }

    auto now = uv_now(loop_);

    for (auto it = range.first; it != range.second;) {
      auto &ent = (*it).second;
      if (ent->stale) {
        ++it;
        continue;
      }
      if (need_validation_file_entry(ent.get(), now) &&
          !validate_file_entry(ent.get(), now)) {
        if (ent->usecount == 0) {
          fd_cache_lru_.remove(ent.get());
          close(ent->fd);
          it = fd_cache_.erase(it);
          continue;
        }
        ++it;
        continue;
      }

      fd_cache_lru_.remove(ent.get());
      fd_cache_lru_.append(ent.get());

      ++ent->usecount;
      return ent.get();
    }
    return nullptr;
  }
  FileEntry *cache_fd(const std::string &path, const FileEntry &ent) {
#ifdef HAVE_STD_MAP_EMPLACE
    auto rv = fd_cache_.emplace(path, make_unique<FileEntry>(ent));
#else  // !HAVE_STD_MAP_EMPLACE
    // for gcc-4.7
    auto rv =
        fd_cache_.insert(std::make_pair(path, make_unique<FileEntry>(ent)));
#endif // !HAVE_STD_MAP_EMPLACE
    auto &res = (*rv).second;
    res->it = rv;
    fd_cache_lru_.append(res.get());

    while (fd_cache_.size() > FILE_ENTRY_EVICT_THRES) {
      auto ent = fd_cache_lru_.head;
      if (ent->usecount) {
        break;
      }
      fd_cache_lru_.remove(ent);
      close(ent->fd);
      fd_cache_.erase(ent->it);
    }

    return res.get();
  }
  void release_fd(FileEntry *target) {
    --target->usecount;

    if (target->usecount == 0 && target->stale) {
      fd_cache_lru_.remove(target);
      close(target->fd);
      fd_cache_.erase(target->it);
      return;
    }

    // We use timer to close file descriptor and delete the entry from
    // cache.  The timer will be started when there is no handler.
  }
  void release_unused_fd() {
    for (auto i = std::begin(fd_cache_); i != std::end(fd_cache_);) {
      auto &ent = (*i).second;
      if (ent->usecount != 0) {
        ++i;
        continue;
      }

      fd_cache_lru_.remove(ent.get());
      close(ent->fd);
      i = fd_cache_.erase(i);
    }
  }
  const HttpServer *get_server() const { return sv_; }
  bool handlers_empty() const { return handlers_.empty(); }

private:
  std::set<Http2Handler *> handlers_;
  // cache for file descriptors to read file.
  std::multimap<std::string, std::unique_ptr<FileEntry>> fd_cache_;
  DList<FileEntry> fd_cache_lru_;
  HttpServer *sv_;
  uv_loop_t *loop_;
  const Config *config_;
  nghttp2_session_callbacks *callbacks_;
  uv_timer_t release_fd_timer_;
  int64_t next_session_id_;
  uint64_t tstamp_cached_;
  std::string cached_date_;
};

namespace {
void release_fd_cb(uv_timer_t *w) {
  auto sessions = static_cast<Sessions *>(w->data);

  uv_timer_stop(w);

  if (!sessions->handlers_empty()) {
    return;
  }

  sessions->release_unused_fd();
}
} // namespace

Stream::Stream(Http2Handler *handler, int32_t stream_id)
    : balloc(1024, 1024),
      header{},
      handler(handler),
      file_ent(nullptr),
      body_length(0),
      body_offset(0),
      header_buffer_size(0),
      stream_id(stream_id),
      echo_upload(false) {

  auto loop = handler->get_loop();
  uv_timer_init(loop, &rtimer);
  uv_timer_init(loop, &wtimer);
  rtimer.data = this;
  wtimer.data = this;
}

Stream::~Stream() {
  if (file_ent != nullptr) {
    auto sessions = handler->get_sessions();
    sessions->release_fd(file_ent);
  }

  auto &rcbuf = header.rcbuf;
  nghttp2_rcbuf_decref(rcbuf.method);
  nghttp2_rcbuf_decref(rcbuf.scheme);
  nghttp2_rcbuf_decref(rcbuf.authority);
  nghttp2_rcbuf_decref(rcbuf.host);
  nghttp2_rcbuf_decref(rcbuf.path);
  nghttp2_rcbuf_decref(rcbuf.ims);
  nghttp2_rcbuf_decref(rcbuf.expect);


  uv_timer_stop(&rtimer);
  uv_timer_stop(&wtimer);
}

namespace {
void on_session_closed(Http2Handler *hd, int64_t session_id) {
  if (hd->get_config()->verbose) {
    print_session_id(session_id);
    print_timer();
    std::cout << " closed" << std::endl;
  }
}
} // namespace

namespace {
void settings_timeout_cb(uv_timer_t *w) {
  int rv;
  auto hd = static_cast<Http2Handler *>(w->data);
  hd->terminate_session(NGHTTP2_SETTINGS_TIMEOUT);
  rv = hd->on_write();
  if (rv == -1) {
    delete_handler(hd);
  }
}
} // namespace

namespace {
neat_error_code on_readable(struct neat_flow_operations *opCB) {
  int rv;
  auto handler = static_cast<Http2Handler *>(opCB->userData);
  rv = handler->on_read();
  if (rv == -1) {
    delete_handler(handler);
    return NEAT_ERROR_IO;
  }

  return NEAT_ERROR_OK;
}
} // namespace

namespace {
neat_error_code on_writable(struct neat_flow_operations *opCB) {
  int rv;
  auto handler = static_cast<Http2Handler *>(opCB->userData);

  rv = handler->on_write();
  if (rv == -1) {
    delete_handler(handler);
    return NEAT_ERROR_IO;
  }
  return NEAT_ERROR_OK;
}
} // namespace

namespace {
neat_error_code on_connected(struct neat_flow_operations *opCB) {
  Sessions *sessions = (Sessions *) opCB->ctx->loop->data;
  auto handler = make_unique<Http2Handler>(sessions, opCB->ctx, opCB->flow, sessions->get_next_session_id());

  if (handler->connection_made() != 0) {
    std::cerr << __func__ << " - connection_made() failed" << std::endl;
    return NEAT_ERROR_IO;
  }

  opCB->on_writable = on_readable;
  opCB->userData = handler.get();
  neat_set_operations(opCB->ctx, opCB->flow, opCB);

  sessions->add_handler(handler.release());

  return NEAT_ERROR_OK;
}
} // namespace

Http2Handler::Http2Handler(Sessions *sessions, neat_ctx *ctx, neat_flow *flow,
                           int64_t session_id)
    : session_id_(session_id),
      session_(nullptr),
      sessions_(sessions),
      data_pending_(nullptr),
      data_pendinglen_(0),
      ctx(ctx),
      flow(flow)
       {

  uv_timer_init(ctx->loop, &settings_timerev_);
  settings_timerev_.data = this;
}

Http2Handler::~Http2Handler() {
  on_session_closed(this, session_id_);
  nghttp2_session_del(session_);
  uv_timer_stop(&settings_timerev_);
}

void Http2Handler::remove_self() { sessions_->remove_handler(this); }

uv_loop_t *Http2Handler::get_loop() const {
  return sessions_->get_loop();
}

Http2Handler::WriteBuf *Http2Handler::get_wb() { return &wb_; }

void Http2Handler::start_settings_timer() {
  uv_timer_start(&settings_timerev_, settings_timeout_cb, 10000, 0);
}

int Http2Handler::fill_wb() {
  if (data_pending_) {
    auto n = std::min(wb_.wleft(), data_pendinglen_);
    wb_.write(data_pending_, n);
    if (n < data_pendinglen_) {
      data_pending_ += n;
      data_pendinglen_ -= n;
      return 0;
    }

    data_pending_ = nullptr;
    data_pendinglen_ = 0;
  }

  for (;;) {
    const uint8_t *data;
    auto datalen = nghttp2_session_mem_send(session_, &data);

    if (datalen < 0) {
      std::cerr << "nghttp2_session_mem_send() returned error: "
                << nghttp2_strerror(datalen) << std::endl;
      return -1;
    }
    if (datalen == 0) {
      break;
    }
    auto n = wb_.write(data, datalen);
    if (n < static_cast<decltype(n)>(datalen)) {
      data_pending_ = data + n;
      data_pendinglen_ = datalen - n;
      break;
    }
  }
  return 0;
}

int Http2Handler::read_clear() {
  int rv;
  std::array<uint8_t, 8_k> buf;
  neat_error_code code;
  uint32_t bytes_read = 0;

  for (;;) {
    code = neat_read(this->ctx, this->flow, buf.data(), buf.size(), &bytes_read, NULL, 0);

    if (code == NEAT_ERROR_WOULD_BLOCK) {
        break;
    } else if (code != NEAT_OK) {
        return -1;
    }

    if (bytes_read == 0) {
      return -1;
    }

    if (get_config()->hexdump) {
      util::hexdump(stdout, buf.data(), bytes_read);
    }

    rv = nghttp2_session_mem_recv(session_, buf.data(), bytes_read);
    if (rv < 0) {
      if (rv != NGHTTP2_ERR_BAD_CLIENT_MAGIC) {
        std::cerr << "nghttp2_session_mem_recv() returned error: "
                  << nghttp2_strerror(rv) << std::endl;
      }
      return -1;
    }
  }

  return write_clear();
}

int Http2Handler::write_clear() {
  neat_error_code code;

  for (;;) {
    if (wb_.rleft() > 0) {
      code = neat_write(this->ctx, this->flow, wb_.pos, wb_.rleft(), NULL, 0);
      if (code == NEAT_ERROR_WOULD_BLOCK) {
        return 0;
      } else if (code != NEAT_OK) {
        return -1;
      }
      wb_.drain(wb_.rleft());
      continue;
    }
    wb_.reset();
    if (fill_wb() != 0) {
      return -1;
    }
    if (wb_.rleft() == 0) {
      break;
    }
  }

  if (wb_.rleft() == 0) {
    ops.on_writable = NULL;
    neat_set_operations(this->ctx, this->flow, &ops);
  } else {
    //ev_io_start(loop, &wev_);
  }

  if (nghttp2_session_want_read(session_) == 0 &&
      nghttp2_session_want_write(session_) == 0 && wb_.rleft() == 0) {
    return -1;
  }

  return 0;
}

int Http2Handler::on_read() { return read_clear(); }

int Http2Handler::on_write() { return write_clear(); }

int Http2Handler::connection_made() {
  int r;

  r = nghttp2_session_server_new(&session_, sessions_->get_callbacks(), this);

  if (r != 0) {
    return r;
  }

  auto config = sessions_->get_config();
  std::array<nghttp2_settings_entry, 4> entry;
  size_t niv = 1;

  entry[0].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  entry[0].value = config->max_concurrent_streams;

  if (config->header_table_size >= 0) {
    entry[niv].settings_id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE;
    entry[niv].value = config->header_table_size;
    ++niv;
  }

  if (config->window_bits != -1) {
    entry[niv].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
    entry[niv].value = (1 << config->window_bits) - 1;
    ++niv;
  }

  r = nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, entry.data(), niv);
  if (r != 0) {
    return r;
  }

  if (config->connection_window_bits != -1) {
    r = nghttp2_session_set_local_window_size(
        session_, NGHTTP2_FLAG_NONE, 0,
        (1 << config->connection_window_bits) - 1);
    if (r != 0) {
      return r;
    }
  }

  return on_write();
}

int Http2Handler::submit_file_response(const StringRef &status, Stream *stream,
                                       time_t last_modified, off_t file_length,
                                       const std::string *content_type,
                                       nghttp2_data_provider *data_prd) {
  std::string last_modified_str;
  auto nva = make_array(http2::make_nv_ls_nocopy(":status", status),
                        http2::make_nv_ls_nocopy("server", NGHTTPD_SERVER),
                        http2::make_nv_ll("cache-control", "max-age=3600"),
                        http2::make_nv_ls("date", sessions_->get_cached_date()),
                        http2::make_nv_ll("", ""), http2::make_nv_ll("", ""),
                        http2::make_nv_ll("", ""), http2::make_nv_ll("", ""));
  size_t nvlen = 4;
  if (!get_config()->no_content_length) {
    nva[nvlen++] = http2::make_nv_ls_nocopy(
        "content-length",
        util::make_string_ref_uint(stream->balloc, file_length));
  }
  if (last_modified != 0) {
    last_modified_str = util::http_date(last_modified);
    nva[nvlen++] = http2::make_nv_ls("last-modified", last_modified_str);
  }
  if (content_type) {
    nva[nvlen++] = http2::make_nv_ls("content-type", *content_type);
  }
  auto &trailer_names = get_config()->trailer_names;
  if (!trailer_names.empty()) {
    nva[nvlen++] = http2::make_nv_ls_nocopy("trailer", trailer_names);
  }
  return nghttp2_submit_response(session_, stream->stream_id, nva.data(), nvlen,
                                 data_prd);
}

int Http2Handler::submit_response(const StringRef &status, int32_t stream_id,
                                  const HeaderRefs &headers,
                                  nghttp2_data_provider *data_prd) {
  auto nva = std::vector<nghttp2_nv>();
  nva.reserve(4 + headers.size());
  nva.push_back(http2::make_nv_ls_nocopy(":status", status));
  nva.push_back(http2::make_nv_ls_nocopy("server", NGHTTPD_SERVER));
  nva.push_back(http2::make_nv_ls("date", sessions_->get_cached_date()));

  if (data_prd) {
    auto &trailer_names = get_config()->trailer_names;
    if (!trailer_names.empty()) {
      nva.push_back(http2::make_nv_ls_nocopy("trailer", trailer_names));
    }
  }

  for (auto &nv : headers) {
    nva.push_back(http2::make_nv_nocopy(nv.name, nv.value, nv.no_index));
  }
  int r = nghttp2_submit_response(session_, stream_id, nva.data(), nva.size(),
                                  data_prd);
  return r;
}

int Http2Handler::submit_response(const StringRef &status, int32_t stream_id,
                                  nghttp2_data_provider *data_prd) {
  auto nva = make_array(http2::make_nv_ls_nocopy(":status", status),
                        http2::make_nv_ls_nocopy("server", NGHTTPD_SERVER),
                        http2::make_nv_ls("date", sessions_->get_cached_date()),
                        http2::make_nv_ll("", ""));
  size_t nvlen = 3;

  if (data_prd) {
    auto &trailer_names = get_config()->trailer_names;
    if (!trailer_names.empty()) {
      nva[nvlen++] = http2::make_nv_ls_nocopy("trailer", trailer_names);
    }
  }

  return nghttp2_submit_response(session_, stream_id, nva.data(), nvlen,
                                 data_prd);
}

int Http2Handler::submit_non_final_response(const std::string &status,
                                            int32_t stream_id) {
  auto nva = make_array(http2::make_nv_ls(":status", status));
  return nghttp2_submit_headers(session_, NGHTTP2_FLAG_NONE, stream_id, nullptr,
                                nva.data(), nva.size(), nullptr);
}

int Http2Handler::submit_push_promise(Stream *stream,
                                      const StringRef &push_path) {
  auto authority = stream->header.authority;

  if (authority.empty()) {
    authority = stream->header.host;
  }

  auto scheme = get_config()->no_tls ? StringRef::from_lit("http")
                                     : StringRef::from_lit("https");

  auto nva = make_array(http2::make_nv_ll(":method", "GET"),
                        http2::make_nv_ls_nocopy(":path", push_path),
                        http2::make_nv_ls_nocopy(":scheme", scheme),
                        http2::make_nv_ls_nocopy(":authority", authority));

  auto promised_stream_id = nghttp2_submit_push_promise(
      session_, NGHTTP2_FLAG_END_HEADERS, stream->stream_id, nva.data(),
      nva.size(), nullptr);

  if (promised_stream_id < 0) {
    return promised_stream_id;
  }

  auto promised_stream = make_unique<Stream>(this, promised_stream_id);

  auto &promised_header = promised_stream->header;
  promised_header.method = StringRef::from_lit("GET");
  promised_header.path = push_path;
  promised_header.scheme = scheme;
  promised_header.authority =
      make_string_ref(promised_stream->balloc, authority);

  add_stream(promised_stream_id, std::move(promised_stream));

  return 0;
}

int Http2Handler::submit_rst_stream(Stream *stream, uint32_t error_code) {
  remove_stream_read_timeout(stream);
  remove_stream_write_timeout(stream);

  return nghttp2_submit_rst_stream(session_, NGHTTP2_FLAG_NONE,
                                   stream->stream_id, error_code);
}

void Http2Handler::add_stream(int32_t stream_id,
                              std::unique_ptr<Stream> stream) {
  id2stream_[stream_id] = std::move(stream);
}

void Http2Handler::remove_stream(int32_t stream_id) {
  id2stream_.erase(stream_id);
}

Stream *Http2Handler::get_stream(int32_t stream_id) {
  auto itr = id2stream_.find(stream_id);
  if (itr == std::end(id2stream_)) {
    return nullptr;
  } else {
    return (*itr).second.get();
  }
}

int64_t Http2Handler::session_id() const { return session_id_; }

Sessions *Http2Handler::get_sessions() const { return sessions_; }

const Config *Http2Handler::get_config() const {
  return sessions_->get_config();
}

void Http2Handler::remove_settings_timer() {
  uv_timer_stop(&settings_timerev_);
}

void Http2Handler::terminate_session(uint32_t error_code) {
  nghttp2_session_terminate_session(session_, error_code);
}

ssize_t file_read_callback(nghttp2_session *session, int32_t stream_id,
                           uint8_t *buf, size_t length, uint32_t *data_flags,
                           nghttp2_data_source *source, void *user_data) {
  int rv;
  auto hd = static_cast<Http2Handler *>(user_data);
  auto stream = hd->get_stream(stream_id);

  auto nread = std::min(stream->body_length - stream->body_offset,
                        static_cast<int64_t>(length));

  *data_flags |= NGHTTP2_DATA_FLAG_NO_COPY;

  if (nread == 0 || stream->body_length == stream->body_offset + nread) {
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;

    auto config = hd->get_config();
    if (!config->trailer.empty()) {
      std::vector<nghttp2_nv> nva;
      nva.reserve(config->trailer.size());
      for (auto &kv : config->trailer) {
        nva.push_back(http2::make_nv(kv.name, kv.value, kv.no_index));
      }
      rv = nghttp2_submit_trailer(session, stream_id, nva.data(), nva.size());
      if (rv != 0) {
        if (nghttp2_is_fatal(rv)) {
          return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
      } else {
        *data_flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
      }
    }

    if (nghttp2_session_get_stream_remote_close(session, stream_id) == 0) {
      remove_stream_read_timeout(stream);
      remove_stream_write_timeout(stream);

      hd->submit_rst_stream(stream, NGHTTP2_NO_ERROR);
    }
  }

  return nread;
}

namespace {
void prepare_status_response(Stream *stream, Http2Handler *hd, int status) {
  auto sessions = hd->get_sessions();
  auto status_page = sessions->get_server()->get_status_page(status);
  auto file_ent = &status_page->file_ent;

  // we don't set stream->file_ent since we don't want to expire it.
  stream->body_length = file_ent->length;
  nghttp2_data_provider data_prd;
  data_prd.source.fd = file_ent->fd;
  data_prd.read_callback = file_read_callback;

  HeaderRefs headers;
  headers.reserve(2);
  headers.emplace_back(StringRef::from_lit("content-type"),
                       StringRef::from_lit("text/html; charset=UTF-8"));
  headers.emplace_back(
      StringRef::from_lit("content-length"),
      util::make_string_ref_uint(stream->balloc, file_ent->length));
  hd->submit_response(StringRef{status_page->status}, stream->stream_id,
                      headers, &data_prd);
}
} // namespace

namespace {
void prepare_echo_response(Stream *stream, Http2Handler *hd) {
  auto length = lseek(stream->file_ent->fd, 0, SEEK_END);
  if (length == -1) {
    hd->submit_rst_stream(stream, NGHTTP2_INTERNAL_ERROR);
    return;
  }
  stream->body_length = length;
  if (lseek(stream->file_ent->fd, 0, SEEK_SET) == -1) {
    hd->submit_rst_stream(stream, NGHTTP2_INTERNAL_ERROR);
    return;
  }
  nghttp2_data_provider data_prd;
  data_prd.source.fd = stream->file_ent->fd;
  data_prd.read_callback = file_read_callback;

  HeaderRefs headers;
  headers.emplace_back(StringRef::from_lit("nghttpd-response"),
                       StringRef::from_lit("echo"));
  if (!hd->get_config()->no_content_length) {
    headers.emplace_back(StringRef::from_lit("content-length"),
                         util::make_string_ref_uint(stream->balloc, length));
  }

  hd->submit_response(StringRef::from_lit("200"), stream->stream_id, headers,
                      &data_prd);
}
} // namespace

namespace {
bool prepare_upload_temp_store(Stream *stream, Http2Handler *hd) {
  auto sessions = hd->get_sessions();

  char tempfn[] = "/tmp/nghttpd.temp.XXXXXX";
  auto fd = mkstemp(tempfn);
  if (fd == -1) {
    return false;
  }
  unlink(tempfn);
  // Ordinary request never start with "echo:".  The length is 0 for
  // now.  We will update it when we get whole request body.
  auto path = std::string("echo:") + tempfn;
  stream->file_ent =
      sessions->cache_fd(path, FileEntry(path, 0, 0, fd, nullptr, 0, true));
  stream->echo_upload = true;
  return true;
}
} // namespace

namespace {
void prepare_redirect_response(Stream *stream, Http2Handler *hd,
                               const StringRef &path, int status) {
  auto scheme = stream->header.scheme;

  auto authority = stream->header.authority;
  if (authority.empty()) {
    authority = stream->header.host;
  }

  auto location = concat_string_ref(
      stream->balloc, scheme, StringRef::from_lit("://"), authority, path);

  auto headers = HeaderRefs{{StringRef::from_lit("location"), location}};

  auto sessions = hd->get_sessions();
  auto status_page = sessions->get_server()->get_status_page(status);

  hd->submit_response(StringRef{status_page->status}, stream->stream_id,
                      headers, nullptr);
}
} // namespace

namespace {
void prepare_response(Stream *stream, Http2Handler *hd,
                      bool allow_push = true) {
  int rv;
  auto reqpath = stream->header.path;
  if (reqpath.empty()) {
    prepare_status_response(stream, hd, 405);
    return;
  }

  auto ims = stream->header.ims;

  time_t last_mod = 0;
  bool last_mod_found = false;
  if (!ims.empty()) {
    last_mod_found = true;
    last_mod = util::parse_http_date(ims);
  }

  StringRef raw_path, raw_query;
  auto query_pos = std::find(std::begin(reqpath), std::end(reqpath), '?');
  if (query_pos != std::end(reqpath)) {
    // Do not response to this request to allow clients to test timeouts.
    if (util::streq_l("nghttpd_do_not_respond_to_req=yes",
                      StringRef{query_pos, std::end(reqpath)})) {
      return;
    }
    raw_path = StringRef{std::begin(reqpath), query_pos};
    raw_query = StringRef{query_pos, std::end(reqpath)};
  } else {
    raw_path = reqpath;
  }

  auto sessions = hd->get_sessions();

  StringRef path;
  if (std::find(std::begin(raw_path), std::end(raw_path), '%') ==
      std::end(raw_path)) {
    path = raw_path;
  } else {
    path = util::percent_decode(stream->balloc, raw_path);
  }

  path = http2::path_join(stream->balloc, StringRef{}, StringRef{}, path,
                          StringRef{});

  if (std::find(std::begin(path), std::end(path), '\\') != std::end(path)) {
    if (stream->file_ent) {
      sessions->release_fd(stream->file_ent);
      stream->file_ent = nullptr;
    }
    prepare_status_response(stream, hd, 404);
    return;
  }

  if (!hd->get_config()->push.empty()) {
    auto push_itr = hd->get_config()->push.find(path.str());
    if (allow_push && push_itr != std::end(hd->get_config()->push)) {
      for (auto &push_path : (*push_itr).second) {
        rv = hd->submit_push_promise(stream, StringRef{push_path});
        if (rv != 0) {
          std::cerr << "nghttp2_submit_push_promise() returned error: "
                    << nghttp2_strerror(rv) << std::endl;
        }
      }
    }
  }

  std::string file_path;
  {
    auto len = hd->get_config()->htdocs.size() + path.size();

    auto trailing_slash = path[path.size() - 1] == '/';
    if (trailing_slash) {
      len += DEFAULT_HTML.size();
    }

    file_path.resize(len);

    auto p = &file_path[0];

    auto &htdocs = hd->get_config()->htdocs;
    p = std::copy(std::begin(htdocs), std::end(htdocs), p);
    p = std::copy(std::begin(path), std::end(path), p);
    if (trailing_slash) {
      std::copy(std::begin(DEFAULT_HTML), std::end(DEFAULT_HTML), p);
    }
  }

  if (stream->echo_upload) {
    assert(stream->file_ent);
    prepare_echo_response(stream, hd);
    return;
  }

  auto file_ent = sessions->get_cached_fd(file_path);

  if (file_ent == nullptr) {
    int file = open(file_path.c_str(), O_RDONLY | O_BINARY);
    if (file == -1) {
      prepare_status_response(stream, hd, 404);

      return;
    }

    struct stat buf;

    if (fstat(file, &buf) == -1) {
      close(file);
      prepare_status_response(stream, hd, 404);

      return;
    }

    if (buf.st_mode & S_IFDIR) {
      close(file);

      auto reqpath = concat_string_ref(stream->balloc, raw_path,
                                       StringRef::from_lit("/"), raw_query);

      prepare_redirect_response(stream, hd, reqpath, 301);

      return;
    }

    const std::string *content_type = nullptr;

    auto ext = file_path.c_str() + file_path.size() - 1;
    for (; file_path.c_str() < ext && *ext != '.' && *ext != '/'; --ext)
      ;
    if (*ext == '.') {
      ++ext;

      const auto &mime_types = hd->get_config()->mime_types;
      auto content_type_itr = mime_types.find(ext);
      if (content_type_itr != std::end(mime_types)) {
        content_type = &(*content_type_itr).second;
      }
    }

    file_ent = sessions->cache_fd(
        file_path, FileEntry(file_path, buf.st_size, buf.st_mtime, file,
                             content_type, uv_now(sessions->get_loop())));
  }

  stream->file_ent = file_ent;

  if (last_mod_found && file_ent->mtime <= last_mod) {
    hd->submit_response(StringRef::from_lit("304"), stream->stream_id, nullptr);

    return;
  }

  auto method = stream->header.method;
  if (method == StringRef::from_lit("HEAD")) {
    hd->submit_file_response(StringRef::from_lit("200"), stream,
                             file_ent->mtime, file_ent->length,
                             file_ent->content_type, nullptr);
    return;
  }

  stream->body_length = file_ent->length;

  nghttp2_data_provider data_prd;

  data_prd.source.fd = file_ent->fd;
  data_prd.read_callback = file_read_callback;

  hd->submit_file_response(StringRef::from_lit("200"), stream, file_ent->mtime,
                           file_ent->length, file_ent->content_type, &data_prd);
}
} // namespace

namespace {
int on_header_callback2(nghttp2_session *session, const nghttp2_frame *frame,
                        nghttp2_rcbuf *name, nghttp2_rcbuf *value,
                        uint8_t flags, void *user_data) {
  auto hd = static_cast<Http2Handler *>(user_data);

  auto namebuf = nghttp2_rcbuf_get_buf(name);
  auto valuebuf = nghttp2_rcbuf_get_buf(value);

  if (hd->get_config()->verbose) {
    print_session_id(hd->session_id());
    verbose_on_header_callback(session, frame, namebuf.base, namebuf.len,
                               valuebuf.base, valuebuf.len, flags, user_data);
  }
  if (frame->hd.type != NGHTTP2_HEADERS ||
      frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    return 0;
  }
  auto stream = hd->get_stream(frame->hd.stream_id);
  if (!stream) {
    return 0;
  }

  if (stream->header_buffer_size + namebuf.len + valuebuf.len > 64_k) {
    hd->submit_rst_stream(stream, NGHTTP2_INTERNAL_ERROR);
    return 0;
  }

  stream->header_buffer_size += namebuf.len + valuebuf.len;

  auto token = http2::lookup_token(namebuf.base, namebuf.len);

  auto &header = stream->header;

  switch (token) {
  case http2::HD__METHOD:
    header.method = StringRef{valuebuf.base, valuebuf.len};
    header.rcbuf.method = value;
    nghttp2_rcbuf_incref(value);
    break;
  case http2::HD__SCHEME:
    header.scheme = StringRef{valuebuf.base, valuebuf.len};
    header.rcbuf.scheme = value;
    nghttp2_rcbuf_incref(value);
    break;
  case http2::HD__AUTHORITY:
    header.authority = StringRef{valuebuf.base, valuebuf.len};
    header.rcbuf.authority = value;
    nghttp2_rcbuf_incref(value);
    break;
  case http2::HD_HOST:
    header.host = StringRef{valuebuf.base, valuebuf.len};
    header.rcbuf.host = value;
    nghttp2_rcbuf_incref(value);
    break;
  case http2::HD__PATH:
    header.path = StringRef{valuebuf.base, valuebuf.len};
    header.rcbuf.path = value;
    nghttp2_rcbuf_incref(value);
    break;
  case http2::HD_IF_MODIFIED_SINCE:
    header.ims = StringRef{valuebuf.base, valuebuf.len};
    header.rcbuf.ims = value;
    nghttp2_rcbuf_incref(value);
    break;
  case http2::HD_EXPECT:
    header.expect = StringRef{valuebuf.base, valuebuf.len};
    header.rcbuf.expect = value;
    nghttp2_rcbuf_incref(value);
    break;
  }

  return 0;
}
} // namespace

namespace {
int on_begin_headers_callback(nghttp2_session *session,
                              const nghttp2_frame *frame, void *user_data) {
  auto hd = static_cast<Http2Handler *>(user_data);

  if (frame->hd.type != NGHTTP2_HEADERS ||
      frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    return 0;
  }

  auto stream = make_unique<Stream>(hd, frame->hd.stream_id);

  add_stream_read_timeout(stream.get());

  hd->add_stream(frame->hd.stream_id, std::move(stream));

  return 0;
}
} // namespace

namespace {
int hd_on_frame_recv_callback(nghttp2_session *session,
                              const nghttp2_frame *frame, void *user_data) {
  auto hd = static_cast<Http2Handler *>(user_data);
  if (hd->get_config()->verbose) {
    print_session_id(hd->session_id());
    verbose_on_frame_recv_callback(session, frame, user_data);
  }
  switch (frame->hd.type) {
  case NGHTTP2_DATA: {
    // TODO Handle POST
    auto stream = hd->get_stream(frame->hd.stream_id);
    if (!stream) {
      return 0;
    }

    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      remove_stream_read_timeout(stream);
      if (stream->echo_upload || !hd->get_config()->early_response) {
        prepare_response(stream, hd);
      }
    } else {
      add_stream_read_timeout(stream);
    }

    break;
  }
  case NGHTTP2_HEADERS: {
    auto stream = hd->get_stream(frame->hd.stream_id);
    if (!stream) {
      return 0;
    }

    if (frame->headers.cat == NGHTTP2_HCAT_REQUEST) {

      auto expect100 = stream->header.expect;

      if (util::strieq_l("100-continue", expect100)) {
        hd->submit_non_final_response("100", frame->hd.stream_id);
      }

      auto method = stream->header.method;
      if (hd->get_config()->echo_upload &&
          (method == StringRef::from_lit("POST") ||
           method == StringRef::from_lit("PUT"))) {
        if (!prepare_upload_temp_store(stream, hd)) {
          hd->submit_rst_stream(stream, NGHTTP2_INTERNAL_ERROR);
          return 0;
        }
      } else if (hd->get_config()->early_response) {
        prepare_response(stream, hd);
      }
    }

    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      remove_stream_read_timeout(stream);
      if (stream->echo_upload || !hd->get_config()->early_response) {
        prepare_response(stream, hd);
      }
    } else {
      add_stream_read_timeout(stream);
    }

    break;
  }
  case NGHTTP2_SETTINGS:
    if (frame->hd.flags & NGHTTP2_FLAG_ACK) {
      hd->remove_settings_timer();
    }
    break;
  default:
    break;
  }
  return 0;
}
} // namespace

namespace {
int hd_on_frame_send_callback(nghttp2_session *session,
                              const nghttp2_frame *frame, void *user_data) {
  auto hd = static_cast<Http2Handler *>(user_data);

  if (hd->get_config()->verbose) {
    print_session_id(hd->session_id());
    verbose_on_frame_send_callback(session, frame, user_data);
  }

  switch (frame->hd.type) {
  case NGHTTP2_DATA:
  case NGHTTP2_HEADERS: {
    auto stream = hd->get_stream(frame->hd.stream_id);

    if (!stream) {
      return 0;
    }

    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      remove_stream_write_timeout(stream);
    } else if (std::min(nghttp2_session_get_stream_remote_window_size(
                            session, frame->hd.stream_id),
                        nghttp2_session_get_remote_window_size(session)) <= 0) {
      // If stream is blocked by flow control, enable write timeout.
      add_stream_read_timeout_if_pending(stream);
      add_stream_write_timeout(stream);
    } else {
      add_stream_read_timeout_if_pending(stream);
      remove_stream_write_timeout(stream);
    }

    break;
  }
  case NGHTTP2_SETTINGS: {
    if (frame->hd.flags & NGHTTP2_FLAG_ACK) {
      return 0;
    }

    hd->start_settings_timer();

    break;
  }
  case NGHTTP2_PUSH_PROMISE: {
    auto promised_stream_id = frame->push_promise.promised_stream_id;
    auto promised_stream = hd->get_stream(promised_stream_id);
    auto stream = hd->get_stream(frame->hd.stream_id);

    if (!stream || !promised_stream) {
      return 0;
    }

    add_stream_read_timeout_if_pending(stream);
    add_stream_write_timeout(stream);

    prepare_response(promised_stream, hd, /*allow_push */ false);
  }
  }
  return 0;
}
} // namespace

namespace {
int send_data_callback(nghttp2_session *session, nghttp2_frame *frame,
                       const uint8_t *framehd, size_t length,
                       nghttp2_data_source *source, void *user_data) {
  auto hd = static_cast<Http2Handler *>(user_data);
  auto wb = hd->get_wb();
  auto padlen = frame->data.padlen;
  auto stream = hd->get_stream(frame->hd.stream_id);

  if (wb->wleft() < 9 + length + padlen) {
    return NGHTTP2_ERR_WOULDBLOCK;
  }

  int fd = source->fd;

  auto p = wb->last;

  p = std::copy_n(framehd, 9, p);

  if (padlen) {
    *p++ = padlen - 1;
  }

  while (length) {
    ssize_t nread;
    while ((nread = pread(fd, p, length, stream->body_offset)) == -1 &&
           errno == EINTR)
      ;

    if (nread == -1) {
      remove_stream_read_timeout(stream);
      remove_stream_write_timeout(stream);

      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

    stream->body_offset += nread;
    length -= nread;
    p += nread;
  }

  if (padlen) {
    std::fill(p, p + padlen - 1, 0);
    p += padlen - 1;
  }

  wb->last = p;

  return 0;
}
} // namespace

namespace {
ssize_t select_padding_callback(nghttp2_session *session,
                                const nghttp2_frame *frame, size_t max_payload,
                                void *user_data) {
  auto hd = static_cast<Http2Handler *>(user_data);
  return std::min(max_payload, frame->hd.length + hd->get_config()->padding);
}
} // namespace

namespace {
int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
                                int32_t stream_id, const uint8_t *data,
                                size_t len, void *user_data) {
  auto hd = static_cast<Http2Handler *>(user_data);
  auto stream = hd->get_stream(stream_id);

  if (!stream) {
    return 0;
  }

  if (stream->echo_upload) {
    assert(stream->file_ent);
    while (len) {
      ssize_t n;
      while ((n = write(stream->file_ent->fd, data, len)) == -1 &&
             errno == EINTR)
        ;
      if (n == -1) {
        hd->submit_rst_stream(stream, NGHTTP2_INTERNAL_ERROR);
        return 0;
      }
      len -= n;
      data += n;
    }
  }
  // TODO Handle POST

  add_stream_read_timeout(stream);

  return 0;
}
} // namespace

namespace {
int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                             uint32_t error_code, void *user_data) {
  auto hd = static_cast<Http2Handler *>(user_data);
  hd->remove_stream(stream_id);
  if (hd->get_config()->verbose) {
    print_session_id(hd->session_id());
    print_timer();
    printf(" stream_id=%d closed\n", stream_id);
    fflush(stdout);
  }

  hd->ops.on_readable = NULL;
  hd->ops.on_writable = NULL;
  neat_set_operations(hd->ctx, hd->flow, &hd->ops);
  neat_free_flow(hd->flow);

  return 0;
}
} // namespace

namespace {
void fill_callback(nghttp2_session_callbacks *callbacks, const Config *config) {
  nghttp2_session_callbacks_set_on_stream_close_callback(
      callbacks, on_stream_close_callback);

  nghttp2_session_callbacks_set_on_frame_recv_callback(
      callbacks, hd_on_frame_recv_callback);

  nghttp2_session_callbacks_set_on_frame_send_callback(
      callbacks, hd_on_frame_send_callback);

  if (config->verbose) {
    nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(
        callbacks, verbose_on_invalid_frame_recv_callback);

    nghttp2_session_callbacks_set_error_callback(callbacks,
                                                 verbose_error_callback);
  }

  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
      callbacks, on_data_chunk_recv_callback);

  nghttp2_session_callbacks_set_on_header_callback2(callbacks,
                                                    on_header_callback2);

  nghttp2_session_callbacks_set_on_begin_headers_callback(
      callbacks, on_begin_headers_callback);

  nghttp2_session_callbacks_set_send_data_callback(callbacks,
                                                   send_data_callback);

  if (config->padding) {
    nghttp2_session_callbacks_set_select_padding_callback(
        callbacks, select_padding_callback);
  }
}
} // namespace

namespace {
FileEntry make_status_body(int status, uint16_t port) {
  BlockAllocator balloc(1024, 1024);

  auto status_string = http2::get_status_string(balloc, status);

  std::string body;
  body = "<html><head><title>";
  body += status_string;
  body += "</title></head><body><h1>";
  body += status_string;
  body += "</h1><hr><address>";
  body += NGHTTPD_SERVER;
  body += " at port ";
  body += util::utos(port);
  body += "</address>";
  body += "</body></html>";

  char tempfn[] = "/tmp/nghttpd.temp.XXXXXX";
  int fd = mkstemp(tempfn);
  if (fd == -1) {
    auto error = errno;
    std::cerr << "Could not open status response body file: errno=" << error;
    assert(0);
  }
  unlink(tempfn);
  ssize_t nwrite;
  while ((nwrite = write(fd, body.c_str(), body.size())) == -1 &&
         errno == EINTR)
    ;
  if (nwrite == -1) {
    auto error = errno;
    std::cerr << "Could not write status response body into file: errno="
              << error;
    assert(0);
  }

  return FileEntry(util::utos(status), nwrite, 0, fd, nullptr, 0);
}
} // namespace

// index into HttpServer::status_pages_
enum {
  IDX_200,
  IDX_301,
  IDX_400,
  IDX_404,
  IDX_405,
};

HttpServer::HttpServer(const Config *config) : config_(config) {
  status_pages_ = std::vector<StatusPage>{
      {"200", make_status_body(200, config_->port)},
      {"301", make_status_body(301, config_->port)},
      {"400", make_status_body(400, config_->port)},
      {"404", make_status_body(404, config_->port)},
      {"405", make_status_body(405, config_->port)},
  };
}

int HttpServer::run() {


  if ((this->ctx = neat_init_ctx()) == NULL) {
    std::cerr << "[ERROR] neat_init_ctx() failed" << std::endl;
    return -1;
  }

  if ((this->flow = neat_new_flow(this->ctx)) == NULL) {
    std::cerr << "[ERROR] neat_new_flow() failed" << std::endl;
    return -1;
  }

  neat_set_property(this->ctx, this->flow, config_property);
  memset(&ops, 0, sizeof(ops));

  ops.on_connected = on_connected;
  neat_set_operations(this->ctx, this->flow, &ops);
  // wait for on_connected or on_error to be invoked
  if (neat_accept(this->ctx, this->flow, 8080, NULL, 0)) {
      std::cerr << "[ERROR] neat_accept() failed" << std::endl;
      return -1;
  }


  Sessions sessions(this, this->ctx->loop, config_);
  std::cerr << "sessions PTR: " << &sessions << std::endl;
  this->ctx->loop->data = &sessions;

  neat_start_event_loop(this->ctx, NEAT_RUN_DEFAULT);

  return 0;
}

const Config *HttpServer::get_config() const { return config_; }

const StatusPage *HttpServer::get_status_page(int status) const {
  switch (status) {
  case 200:
    return &status_pages_[IDX_200];
  case 301:
    return &status_pages_[IDX_301];
  case 400:
    return &status_pages_[IDX_400];
  case 404:
    return &status_pages_[IDX_404];
  case 405:
    return &status_pages_[IDX_405];
  default:
    assert(0);
  }
  return nullptr;
}

} // namespace nghttp2
