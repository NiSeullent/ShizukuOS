/* SPDX-License-Identifier: GPL-2.0-or-later
 * Real DOS-only diagnostic for the CB43 prerequisite patch. Build with
 * Open Watcom 16-bit DOS. Run before Windows starts, in a writable directory.
 * It records actual interrupt outcomes in CBDOSINT.TXT and sets ERRORLEVEL.
 * It never synthesizes a Windows startup broadcast or a Windows version.
 */
#include <dos.h>
#include <stdio.h>
#include <string.h>
#include <io.h>

static FILE *report;
static unsigned checks, failed;

static void check(int value, const char *name)
{
  ++checks;
  if (!value)
    ++failed;
  fprintf(report, "%s %s\n", value ? "PASS" : "FAIL", name);
  fflush(report);
}

static union REGS mux(unsigned ax, unsigned bx, unsigned dx,
                      struct SREGS *segments)
{
  union REGS in, out;
  memset(&in, 0, sizeof in);
  in.x.ax = ax;
  in.x.bx = bx;
  in.x.dx = dx;
  segread(segments);
  int86x(0x2f, &in, &out, segments);
  return out;
}

int main(void)
{
  struct SREGS segments;
  union REGS out, in;
  unsigned char far *jft;
  unsigned short far *sft;
  unsigned char system_number;
  unsigned short saved_jft_segment, saved_jft_offset;
  int fd;
  static const char sample_name[] = "CBDOSDAT.BIN";

  out = mux(0x1600, 0, 0, &segments);
  if (out.h.al != 0 && out.h.al != 0x80)
  {
    puts("Run CBDOSINT only in plain DOS before Windows starts.");
    return 2;
  }
  report = fopen("CBDOSINT.TXT", "w");
  if (!report)
    return 3;
  fputs("CB43 native DOS prerequisite diagnostic; no Windows boot claim\n", report);
  out = mux(0x1220, 0xffff, 0, &segments);
  check(out.x.cflag && out.h.al == 6, "1220_invalid_handle_AL6");
  out = mux(0x1216, 0xffff, 0, &segments);
  check(out.x.cflag, "1216_invalid_system_number_carry");

  memset(&in, 0, sizeof in);
  segread(&segments);
  segments.ds = FP_SEG(sample_name);
  in.h.ah = 0x3c;
  in.x.dx = FP_OFF(sample_name);
  int86x(0x21, &in, &out, &segments);
  fd = out.x.cflag ? -1 : out.x.ax;
  check(fd >= 0, "actual_DOS_file_open");
  if (fd >= 0)
  {
    out = mux(0x1220, fd, 0, &segments);
    check(!out.x.cflag, "1220_actual_file_JFT_pointer");
    if (!out.x.cflag)
    {
      saved_jft_segment = segments.es;
      saved_jft_offset = out.x.di;
      jft = (unsigned char far *)MK_FP(segments.es, out.x.di);
      system_number = *jft;
      check(system_number != 0xff, "JFT_contains_open_system_number");
      out = mux(0x1216, system_number, 0, &segments);
      check(!out.x.cflag, "1216_resolves_actual_open_file");
      if (!out.x.cflag)
      {
        sft = (unsigned short far *)MK_FP(segments.es, out.x.di);
        check(*sft != 0, "actual_SFT_has_open_reference");
      }
      memset(&in, 0, sizeof in);
      in.h.ah = 0x3e;
      in.x.bx = fd;
      int86(0x21, &in, &out);
      check(!out.x.cflag, "actual_DOS_file_close");
      jft = (unsigned char far *)MK_FP(saved_jft_segment, saved_jft_offset);
      check(*jft == 0xff, "actual_close_clears_JFT_byte");
      memset(&in, 0, sizeof in);
      in.h.ah = 0x3e;
      in.x.bx = fd;
      int86(0x21, &in, &out);
      check(out.x.cflag && out.x.ax == 6, "actual_double_close_invalid_handle_AX6");
    }
    else
    {
      memset(&in, 0, sizeof in);
      in.h.ah = 0x3e;
      in.x.bx = fd;
      int86(0x21, &in, &out);
      check(!out.x.cflag, "actual_DOS_file_close_after_JFT_failure");
    }
    unlink("CBDOSDAT.BIN");
  }

  out = mux(0x1231, 0xffff, 0x8101, &segments);
  check(!out.x.cflag && out.x.ax == 0, "1231_hide_selects_DL_ignores_DH_BX");
  out = mux(0x1231, 1, 0xab02, &segments);
  check(!out.x.cflag && out.x.ax == 0, "1231_report_selects_DL_ignores_DH_BX");
  out = mux(0x1600, 0, 0, &segments);
  check(out.h.al == 0 || out.h.al == 0x80, "report_enable_does_not_invent_Windows");
  out = mux(0x1231, 0, 0xff00, &segments);
  check(out.x.cflag && out.x.ax == 1, "1231_one_shot_load_explicitly_unsupported");
  out = mux(0x1231, 0, 3, &segments);
  check(out.x.cflag && out.x.ax == 1, "1231_selector_3_rejected");
  out = mux(0x1231, 0, 0xffff, &segments);
  check(out.x.cflag && out.x.ax == 1, "1231_selector_255_rejected");
  /* Leave reporting enabled before returning to DOS. */
  out = mux(0x1231, 0, 2, &segments);
  check(!out.x.cflag && out.x.ax == 0, "restore_reporting_state");
  fprintf(report, "CHECKS %u PASS %u FAIL %u\n", checks, checks - failed, failed);
  fclose(report);
  return failed ? 1 : 0;
}
