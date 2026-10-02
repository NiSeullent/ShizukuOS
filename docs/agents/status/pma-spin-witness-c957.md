# c957 bounded spinner witness — production failure remains open

The preserved current two-DLL API guest has321 API checks/0 failures but overall FAIL/QEMU3: first PMA low useful work361<1000. The distinct historical151-app regression passes38/38. Neither receipt is changed by this diagnostic.

One ignored clone copies the verified214-source frozen producer. Only its pma_tests.c changes; production sched.c/arch.c, policies, sleep windows, counters and thresholds remain unchanged. Existing dispatch/pre-EOI IRQ/precharge tick callbacks and the spinner's existing IRQ guard collect1024 fixed records per phase. Snapshots bracket both original windows and the guarded priority swap. Fields include roles/IDs, tick/IRQ sequence, committed loops, precharge run ticks, priority/quantum/grant, coordinator state/wake deadline, RIP/RFLAGS and CPU CR8. Body observations mark the first sample after each selection and sparse committed-loop milestone1001. Dispatch selection occurs before current/context transfer; same-TCB reselection is possible. Dispatch CR8 belongs to the outgoing CPU context. Non-IRQ interrupted-frame fields are unavailable, represented as0. Logging flushes after measurement and joins, before later PMA tests.

Final diagnostic source SHA256 `0dfda8330b5470f806aa998323b8190ef29448c94cb8bbf924687c6229594d84`; patch SHA256 `4447f4cb18171fad5f9a0b18eec73debcf80d5928b0d9de26b5253e748089b03`; ignored build/run driver SHA256 `9f8eb2b643b6af7516c9e46c42ad1a3d6f72b8ca9589d9294b58de10f9042a51`. Independent source review checked observer semantics, phase boundaries and bounded evaluation. Evaluator requires4..1024 contiguous records per phase, two snapshots per worker, stable distinct IDs, monotonic clocks, and unique matching IRQ/tick key sets with identical precharge fields. Body absence remains usable negative evidence.

Actual isolated K64S+stub compilation passes141.61 seconds. `build/pma-c957-spin-witness-v1/build-result.json` SHA256 `9e72dd0b1604cf040b62e61112961311efb35e06ddf16af1e296167a0e36725e`; diagnostic BIN SHA256 `74d5a815f0398dd2a4ae8fb573c8588af53d147ec35694a06070b54dd94dc7dc`. This artifact is not promoted. Exact ELF symbols/disassemblies remain with the captured source and build receipt.

The one actual guest uses the same current-green.img SHA256 `5dbfb4000d6cbedf1a3049b8ddc5eab20512f4f664f4e50d6507ec6abbee995a` and original KVM/pc/256MiB options. It ends22.24 seconds/QEMU3 without timeout. Receipt `build/pma-c957-spin-witness-v1/guest/result.json` SHA256 `fc77a541c6342086f70fc62b3276cff097f6a9016a76a2c405e9232261be089c`; raw serial SHA256 `4208487a50c6c9bb825d27c6eda2863c9980ce57b5df485c1ed091fdf9227362`. All1241 guest input identities and1237 build inputs are observed stable before/after. Independent parent/child audits rehash all source/artifact/driver/serial identities and recompute the602/605 records,320 pairs and zero overflow. Both measured rings span161 ticks:128ms sleep requests end in later coordinator execution; these are not exact128-tick measurement intervals. The receipt's PASS means complete diagnostic capture plus API continuation; production_acceptance=false and diagnostic_guest_all_assertions_pass=false.

| Observation | Actual result |
| --- | --- |
| Phase records |602/605; no overflow;320 uniquely paired worker IRQ/tick entries |
| First two policy windows |144/16 then16/144 charged ticks; useful loops402439/426474; original361 failure not reproduced |
| Later equal-quantum check |FAIL; ticks21/80 and41 preemptions. Its allocation terms pass, so at least one unlogged useful-loop term fails |
| Later refresh check |FAIL; updates2549, first33, low useful loops483 |
| Actual API probe |321/0, app exit0/faulted0 |
| Whole diagnostic guest |FAIL/QEMU3; both later failures retained |

A concrete phase1 low-worker episode is captured at serial lines904–912. Worker0/tid417 is selected at relative tick229 with grant4 and loops3667084. Four paired IRQ/tick records (IRQ230..233) observe precharge run ticks148..151, grant4..1, CR8=0 and the same committed-loop counter3667084. All four interrupted RIPs are `ffffffff8016db49`, exactly pma_spinner+0xe9 in this diagnostic ELF: the load preceding loop increment, immediately after POPF at+0xe8. No body observation appears for that selection. Next selection at tick265 observes a body sample and loops3667085 (serial1035–1036).

Independent exact-ELF review confirms all320 recorded IRQ RIPs:319 inside pma_spinner and one at switch_stacks+0x1c, the RET after POPF. Phase0 first low selection is charged once there and once at pma_spinner entry before its body observation.

This witnesses one finite grant being charged without advancement of the committed-loop counter in this clone. It does not prove absence of all instructions, exact interrupt-return timing, a hardware/software interrupt origin, host timing cause or the cause of the original361 failure. The first policy window succeeds overall; observer instructions, binary/BSS layout and later logging perturb timing. Later failures are outside the captured windows and are not attributed to logging or host load. No production heuristic based only on repeated RIP, no threshold change, and no rerun follows from this evidence.

The original current-DLL guest FAIL remains an open acceptance item. Native Windows98/VMM, Supervisor/SMP, complete current runtime, required modern apps, installer and final ISO remain unverified by these standalone UP results. No private media or NAS is used; existing peer guests and public website are unchanged.
