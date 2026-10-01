#include "engine.h"
#include <string.h>
int iewk_engine_validate(const IEWKEngineV1 *e) {
  size_t i;
  if (!e)
    return IEWK_MISSING_ENGINE;
  if (e->abi != IEWK_ABI_V1 || e->size < sizeof *e)
    return IEWK_BAD_ABI;
  if ((e->capabilities & IEWK_REQUIRED_CAPS) != IEWK_REQUIRED_CAPS ||
      !e->engine_name || !e->engine_name[0] || !e->source_sha256 ||
      !e->create || !e->destroy || !e->navigate || !e->resize || !e->focus ||
      !e->command)
    return IEWK_INCOMPLETE_ENGINE;
  for (i = 0; i < 64; i++) {
    char c = e->source_sha256[i];
    if (!c || !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
      return IEWK_INCOMPLETE_ENGINE;
  }
  return e->source_sha256[64] ? IEWK_INCOMPLETE_ENGINE : IEWK_OK;
}
int iewk_web_url(const char *url, size_t length) {
  size_t i, start, end;
  if (!url || length < 8 || length > IEWK_URL_LIMIT)
    return 0;
  if (length >= 8 && !memcmp(url, "https://", 8))
    start = 8;
  else if (!memcmp(url, "http://", 7))
    start = 7;
  else
    return 0;
  for (i = 0; i < length; i++) {
    unsigned char c = (unsigned char)url[i];
    if (c <= 32 || c >= 127 || c == '\\' || c == '"' || c == '<' || c == '>')
      return 0;
  }
  for (end = start;
       end < length && url[end] != '/' && url[end] != '?' && url[end] != '#';
       end++)
    if (url[end] == '@' || url[end] == '%')
      return 0;
  return end != start;
}
