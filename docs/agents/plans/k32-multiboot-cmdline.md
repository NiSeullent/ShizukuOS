# K32 standalone command-line provider correction

Actual canonical230-source K32 KVM boot fails before self-tests with exit97, because QEMU10.1 supplies the boot-stub image path and the strict Win98 service validator rejects a nonempty unrelated policy. Original result225b74fa and source/archive522a25ee remain in canonical build/pma-integrated-native-cpu-3a83a62/k32-kvm. No CPU scheduler assertions ran there.

Correct only STUB_K32's Multiboot provider: recognize exact advertised boot-loader nameqemu (standard field offset64, optional flag9) and remove its image-name prefix; other loader command lines remain raw. Preserve every explicit argument for the unchanged fail-closed service policy. Refuse malformed/truncated K32 command lines rather than silently discarding a service request. K64 verbatim command line stays unchanged. QEMU raw image filenames containing unescaped spaces remain ambiguous and may be refused; no broader generic-loader filename assumption.

Primary source: QEMU v10.1.0 hw/i386/multiboot.c, https://raw.githubusercontent.com/qemu/qemu/v10.1.0/hw/i386/multiboot.c. The Multiboot specification gives loaders control independent of image name: https://www.gnu.org/software/grub/manual/multiboot/html_node/Boot-information-format.html. Therefore generic-loader first-word stripping is deliberately avoided.

Validation: GCC/Clang actual C provider+service-policy boundary fixtures, stricti486 shared stub compilation, actual K32 KVM/TCG native perCPU/selftest gates, negative explicit service/unknown policy boot profiles; pre/post compiler-discovered source/helper/artifact maps and independently reviewed frozen successor. No service-policy/main/IPC/ABI/scheduler mutation; no Windows/VMM/SMP acceptance claim.
