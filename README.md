# kurasagi

`kurasagi` is full POC of PatchGuard bypass for Windows 24H2, Build 26100.4351.

For more information, please refer to the `product` branch, which contains the PDF paper detailing the bypass.

## Changelog

(2025/08/03) **����**: 26100.4652 �������� ���׷��̵� �߽��ϴ�. 26100.4351 ������ ���� Bypass�� Ŀ�� `80650b9cb71855042659137ecd8936f8a9336a61` �� �������ּ���.

## Disclaimers

1. **PLEASE USE IT FOR ONLY EDUCATIONAL PURPOSES!**
2. Do not turn on hypervisor-based security factors when running! (It will BSOD!)
3. Use [kdmapper](https://github.com/TheCruZ/kdmapper) for driver loading.
4. ~~We just found that if we hook well-used functions, it will cause unknown BSOD. Just don't do that.~~ NonPagedPoolExecute�� �Ҵ��� �� `kurasagi`�� �ε��Ǿ� ���� ��� PTE�� ���ڱ� NX ��Ʈ�� �����Ǵ� ���� Ȯ���߽��ϴ�. ������ �𸣰ڳ׿�. �ذ��߽��ϴ�.

# Images

![proof](assets/proof.png)