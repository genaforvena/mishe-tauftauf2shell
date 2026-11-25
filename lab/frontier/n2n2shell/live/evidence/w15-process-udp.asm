
/tmp/n2n2shell-w15.2071415/src/n2n-dc7324af16b2ff3e2b22961e7d8dffcb14f3f6ff/supernode:     file format elf64-x86-64


Disassembly of section .text:

000000000040cbc0 <process_udp.isra.0>:
  40cbc0:	55                   	push   %rbp
  40cbc1:	66 0f ef c0          	pxor   %xmm0,%xmm0
  40cbc5:	48 89 e5             	mov    %rsp,%rbp
  40cbc8:	41 57                	push   %r15
  40cbca:	4d 89 cf             	mov    %r9,%r15
  40cbcd:	41 56                	push   %r14
  40cbcf:	41 55                	push   %r13
  40cbd1:	41 54                	push   %r12
  40cbd3:	53                   	push   %rbx
  40cbd4:	48 8d 9d 00 f1 ff ff 	lea    -0xf00(%rbp),%rbx
  40cbdb:	48 81 ec 98 0f 00 00 	sub    $0xf98,%rsp
  40cbe2:	89 95 6c f0 ff ff    	mov    %edx,-0xf94(%rbp)
  40cbe8:	89 8d 80 f0 ff ff    	mov    %ecx,-0xf80(%rbp)
  40cbee:	4c 89 85 b8 f0 ff ff 	mov    %r8,-0xf48(%rbp)
  40cbf5:	4c 89 8d c0 f0 ff ff 	mov    %r9,-0xf40(%rbp)
  40cbfc:	48 89 bd 98 f0 ff ff 	mov    %rdi,-0xf68(%rbp)
  40cc03:	48 89 df             	mov    %rbx,%rdi
  40cc06:	48 89 b5 78 f0 ff ff 	mov    %rsi,-0xf88(%rbp)
  40cc0d:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
  40cc14:	00 00 
  40cc16:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
  40cc1a:	31 c0                	xor    %eax,%eax
  40cc1c:	0f 29 85 80 f2 ff ff 	movaps %xmm0,-0xd80(%rbp)
  40cc23:	66 0f ef c0          	pxor   %xmm0,%xmm0
  40cc27:	0f 29 85 00 f1 ff ff 	movaps %xmm0,-0xf00(%rbp)
  40cc2e:	48 89 9d b0 f0 ff ff 	mov    %rbx,-0xf50(%rbp)
  40cc35:	c7 85 10 f1 ff ff 00 	movl   $0x0,-0xef0(%rbp)
  40cc3c:	00 00 00 
  40cc3f:	e8 fc df 00 00       	call   41ac40 <fill_n2nsock>
  40cc44:	48 8d 85 b0 f2 ff ff 	lea    -0xd50(%rbp),%rax
  40cc4b:	48 89 de             	mov    %rbx,%rsi
  40cc4e:	48 89 c7             	mov    %rax,%rdi
  40cc51:	48 89 85 70 f0 ff ff 	mov    %rax,-0xf90(%rbp)
  40cc58:	e8 13 89 ff ff       	call   405570 <sock_to_cstr>
  40cc5d:	4d 89 f8             	mov    %r15,%r8
  40cc60:	48 8d 0d e9 60 01 00 	lea    0x160e9(%rip),%rcx        # 422d50 <_IO_stdin_used+0x1d50>
  40cc67:	ba 2c 06 00 00       	mov    $0x62c,%edx
  40cc6c:	49 89 c1             	mov    %rax,%r9
  40cc6f:	48 8d 35 7f 7c 01 00 	lea    0x17c7f(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40cc76:	31 c0                	xor    %eax,%eax
  40cc78:	bf 04 00 00 00       	mov    $0x4,%edi
  40cc7d:	e8 ee 76 ff ff       	call   404370 <_traceEvent>
  40cc82:	49 83 ff 17          	cmp    $0x17,%r15
  40cc86:	0f 86 64 3b 00 00    	jbe    4107f0 <process_udp.isra.0+0x3c30>
  40cc8c:	48 8b 85 98 f0 ff ff 	mov    -0xf68(%rbp),%rax
  40cc93:	48 8b 80 b0 00 00 00 	mov    0xb0(%rax),%rax
  40cc9a:	48 89 85 c8 f0 ff ff 	mov    %rax,-0xf38(%rbp)
  40cca1:	48 8b 85 b8 f0 ff ff 	mov    -0xf48(%rbp),%rax
  40cca8:	80 78 17 00          	cmpb   $0x0,0x17(%rax)
  40ccac:	0f 84 16 01 00 00    	je     40cdc8 <process_udp.isra.0+0x208>
  40ccb2:	48 8b b5 c8 f0 ff ff 	mov    -0xf38(%rbp),%rsi
  40ccb9:	48 85 f6             	test   %rsi,%rsi
  40ccbc:	0f 84 be 00 00 00    	je     40cd80 <process_udp.isra.0+0x1c0>
  40ccc2:	48 8b 8d c0 f0 ff ff 	mov    -0xf40(%rbp),%rcx
  40ccc9:	b8 10 00 00 00       	mov    $0x10,%eax
  40ccce:	4c 8b b6 80 00 00 00 	mov    0x80(%rsi),%r14
  40ccd5:	4c 8d a5 e8 f0 ff ff 	lea    -0xf18(%rbp),%r12
  40ccdc:	4c 8b bd b8 f0 ff ff 	mov    -0xf48(%rbp),%r15
  40cce3:	39 c1                	cmp    %eax,%ecx
  40cce5:	0f 4d c1             	cmovge %ecx,%eax
  40cce8:	41 89 c5             	mov    %eax,%r13d
  40cceb:	8d 40 f0             	lea    -0x10(%rax),%eax
  40ccee:	48 63 d8             	movslq %eax,%rbx
  40ccf1:	48 89 9d c8 f0 ff ff 	mov    %rbx,-0xf38(%rbp)
  40ccf8:	4c 89 f3             	mov    %r14,%rbx
  40ccfb:	49 89 f6             	mov    %rsi,%r14
  40ccfe:	41 80 7e 16 01       	cmpb   $0x1,0x16(%r14)
  40cd03:	74 63                	je     40cd68 <process_udp.isra.0+0x1a8>
  40cd05:	0f 1f 00             	nopl   (%rax)
  40cd08:	49 8b 4e 20          	mov    0x20(%r14),%rcx
  40cd0c:	4d 8b 46 30          	mov    0x30(%r14),%r8
  40cd10:	4d 89 e1             	mov    %r12,%r9
  40cd13:	4c 89 f2             	mov    %r14,%rdx
  40cd16:	0f b7 b5 c0 f0 ff ff 	movzwl -0xf40(%rbp),%esi
  40cd1d:	4c 89 ff             	mov    %r15,%rdi
  40cd20:	e8 eb 13 01 00       	call   41e110 <packet_header_decrypt>
  40cd25:	85 c0                	test   %eax,%eax
  40cd27:	0f 85 27 02 00 00    	jne    40cf54 <process_udp.isra.0+0x394>
  40cd2d:	48 8b 95 c8 f0 ff ff 	mov    -0xf38(%rbp),%rdx
  40cd34:	48 8d bd 80 f2 ff ff 	lea    -0xd80(%rbp),%rdi
  40cd3b:	4c 89 fe             	mov    %r15,%rsi
  40cd3e:	e8 0d 9a ff ff       	call   406750 <pearson_hash_128>
  40cd43:	41 8d 75 f0          	lea    -0x10(%r13),%esi
  40cd47:	49 8b 4e 18          	mov    0x18(%r14),%rcx
  40cd4b:	4d 89 e1             	mov    %r12,%r9
  40cd4e:	4d 8b 46 28          	mov    0x28(%r14),%r8
  40cd52:	0f b7 f6             	movzwl %si,%esi
  40cd55:	4c 89 f2             	mov    %r14,%rdx
  40cd58:	4c 89 ff             	mov    %r15,%rdi
  40cd5b:	e8 b0 13 01 00       	call   41e110 <packet_header_decrypt>
  40cd60:	85 c0                	test   %eax,%eax
  40cd62:	0f 85 a6 03 00 00    	jne    40d10e <process_udp.isra.0+0x54e>
  40cd68:	48 85 db             	test   %rbx,%rbx
  40cd6b:	74 13                	je     40cd80 <process_udp.isra.0+0x1c0>
  40cd6d:	49 89 de             	mov    %rbx,%r14
  40cd70:	48 8b 9b 80 00 00 00 	mov    0x80(%rbx),%rbx
  40cd77:	41 80 7e 16 01       	cmpb   $0x1,0x16(%r14)
  40cd7c:	75 8a                	jne    40cd08 <process_udp.isra.0+0x148>
  40cd7e:	eb e8                	jmp    40cd68 <process_udp.isra.0+0x1a8>
  40cd80:	48 8d 0d f1 60 01 00 	lea    0x160f1(%rip),%rcx        # 422e78 <_IO_stdin_used+0x1e78>
  40cd87:	ba 7a 06 00 00       	mov    $0x67a,%edx
  40cd8c:	48 8d 35 62 7b 01 00 	lea    0x17b62(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40cd93:	31 c0                	xor    %eax,%eax
  40cd95:	bf 04 00 00 00       	mov    $0x4,%edi
  40cd9a:	e8 d1 75 ff ff       	call   404370 <_traceEvent>
  40cd9f:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
  40cda3:	64 48 2b 04 25 28 00 	sub    %fs:0x28,%rax
  40cdaa:	00 00 
  40cdac:	0f 85 e8 41 00 00    	jne    410f9a <process_udp.isra.0+0x43da>
  40cdb2:	48 8d 65 d8          	lea    -0x28(%rbp),%rsp
  40cdb6:	5b                   	pop    %rbx
  40cdb7:	41 5c                	pop    %r12
  40cdb9:	41 5d                	pop    %r13
  40cdbb:	41 5e                	pop    %r14
  40cdbd:	41 5f                	pop    %r15
  40cdbf:	5d                   	pop    %rbp
  40cdc0:	c3                   	ret
  40cdc1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  40cdc8:	80 38 03             	cmpb   $0x3,(%rax)
  40cdcb:	0f 85 e1 fe ff ff    	jne    40ccb2 <process_udp.isra.0+0xf2>
  40cdd1:	48 89 c6             	mov    %rax,%rsi
  40cdd4:	0f b7 40 02          	movzwl 0x2(%rax),%eax
  40cdd8:	89 c2                	mov    %eax,%edx
  40cdda:	0f b6 c4             	movzbl %ah,%eax
  40cddd:	83 e0 1f             	and    $0x1f,%eax
  40cde0:	66 c1 c2 08          	rol    $0x8,%dx
  40cde4:	66 83 f8 0b          	cmp    $0xb,%ax
  40cde8:	0f 87 c4 fe ff ff    	ja     40ccb2 <process_udp.isra.0+0xf2>
  40cdee:	66 83 fa 7f          	cmp    $0x7f,%dx
  40cdf2:	0f 87 ba fe ff ff    	ja     40ccb2 <process_udp.isra.0+0xf2>
  40cdf8:	4c 8d 66 04          	lea    0x4(%rsi),%r12
  40cdfc:	4c 89 e7             	mov    %r12,%rdi
  40cdff:	e8 ac 57 ff ff       	call   4025b0 <strlen@plt>
  40ce04:	48 83 bd c8 f0 ff ff 	cmpq   $0x0,-0xf38(%rbp)
  40ce0b:	00 
  40ce0c:	49 89 c1             	mov    %rax,%r9
  40ce0f:	0f 84 b4 2f 00 00    	je     40fdc9 <process_udp.isra.0+0x3209>
  40ce15:	41 89 c7             	mov    %eax,%r15d
  40ce18:	83 f8 0b             	cmp    $0xb,%eax
  40ce1b:	0f 86 bd 3d 00 00    	jbe    410bde <process_udp.isra.0+0x401e>
  40ce21:	41 89 c0             	mov    %eax,%r8d
  40ce24:	4c 89 e7             	mov    %r12,%rdi
  40ce27:	b8 ef be ed fe       	mov    $0xfeedbeef,%eax
  40ce2c:	ba b9 79 37 9e       	mov    $0x9e3779b9,%edx
  40ce31:	b9 b9 79 37 9e       	mov    $0x9e3779b9,%ecx
  40ce36:	0f b6 77 05          	movzbl 0x5(%rdi),%esi
  40ce3a:	44 0f b6 57 06       	movzbl 0x6(%rdi),%r10d
  40ce3f:	c1 e6 08             	shl    $0x8,%esi
  40ce42:	41 c1 e2 10          	shl    $0x10,%r10d
  40ce46:	44 01 d6             	add    %r10d,%esi
  40ce49:	44 0f b6 57 04       	movzbl 0x4(%rdi),%r10d
  40ce4e:	44 01 d6             	add    %r10d,%esi
  40ce51:	44 0f b6 57 07       	movzbl 0x7(%rdi),%r10d
  40ce56:	41 c1 e2 18          	shl    $0x18,%r10d
  40ce5a:	44 01 d6             	add    %r10d,%esi
  40ce5d:	44 0f b6 57 0a       	movzbl 0xa(%rdi),%r10d
  40ce62:	01 f2                	add    %esi,%edx
  40ce64:	0f b6 77 09          	movzbl 0x9(%rdi),%esi
  40ce68:	41 c1 e2 10          	shl    $0x10,%r10d
  40ce6c:	c1 e6 08             	shl    $0x8,%esi
  40ce6f:	44 01 d6             	add    %r10d,%esi
  40ce72:	44 0f b6 57 08       	movzbl 0x8(%rdi),%r10d
  40ce77:	44 01 d6             	add    %r10d,%esi
  40ce7a:	44 0f b6 57 0b       	movzbl 0xb(%rdi),%r10d
  40ce7f:	41 c1 e2 18          	shl    $0x18,%r10d
  40ce83:	44 01 d6             	add    %r10d,%esi
  40ce86:	44 0f b6 57 02       	movzbl 0x2(%rdi),%r10d
  40ce8b:	01 f0                	add    %esi,%eax
  40ce8d:	0f b6 77 01          	movzbl 0x1(%rdi),%esi
  40ce91:	41 c1 e2 10          	shl    $0x10,%r10d
  40ce95:	c1 e6 08             	shl    $0x8,%esi
  40ce98:	44 01 d6             	add    %r10d,%esi
  40ce9b:	44 0f b6 17          	movzbl (%rdi),%r10d
  40ce9f:	44 01 d6             	add    %r10d,%esi
  40cea2:	44 0f b6 57 03       	movzbl 0x3(%rdi),%r10d
  40cea7:	41 c1 e2 18          	shl    $0x18,%r10d
  40ceab:	44 01 d6             	add    %r10d,%esi
  40ceae:	29 d6                	sub    %edx,%esi
  40ceb0:	29 c2                	sub    %eax,%edx
  40ceb2:	29 c6                	sub    %eax,%esi
  40ceb4:	01 f1                	add    %esi,%ecx
  40ceb6:	89 c6                	mov    %eax,%esi
  40ceb8:	c1 ee 0d             	shr    $0xd,%esi
  40cebb:	31 f1                	xor    %esi,%ecx
  40cebd:	89 d6                	mov    %edx,%esi
  40cebf:	89 ca                	mov    %ecx,%edx
  40cec1:	29 ce                	sub    %ecx,%esi
  40cec3:	29 c8                	sub    %ecx,%eax
  40cec5:	c1 e2 08             	shl    $0x8,%edx
  40cec8:	31 f2                	xor    %esi,%edx
  40ceca:	29 d0                	sub    %edx,%eax
  40cecc:	89 c6                	mov    %eax,%esi
  40cece:	89 d0                	mov    %edx,%eax
  40ced0:	c1 e8 0d             	shr    $0xd,%eax
  40ced3:	31 f0                	xor    %esi,%eax
  40ced5:	29 d1                	sub    %edx,%ecx
  40ced7:	41 83 e8 0c          	sub    $0xc,%r8d
  40cedb:	48 83 c7 0c          	add    $0xc,%rdi
  40cedf:	89 ce                	mov    %ecx,%esi
  40cee1:	89 c1                	mov    %eax,%ecx
  40cee3:	29 c2                	sub    %eax,%edx
  40cee5:	29 c6                	sub    %eax,%esi
  40cee7:	c1 e9 0c             	shr    $0xc,%ecx
  40ceea:	31 f1                	xor    %esi,%ecx
  40ceec:	89 d6                	mov    %edx,%esi
  40ceee:	89 ca                	mov    %ecx,%edx
  40cef0:	29 ce                	sub    %ecx,%esi
  40cef2:	29 c8                	sub    %ecx,%eax
  40cef4:	c1 e2 10             	shl    $0x10,%edx
  40cef7:	31 f2                	xor    %esi,%edx
  40cef9:	29 d0                	sub    %edx,%eax
  40cefb:	29 d1                	sub    %edx,%ecx
  40cefd:	89 c6                	mov    %eax,%esi
  40ceff:	89 d0                	mov    %edx,%eax
  40cf01:	c1 e8 05             	shr    $0x5,%eax
  40cf04:	31 f0                	xor    %esi,%eax
  40cf06:	89 ce                	mov    %ecx,%esi
  40cf08:	89 c1                	mov    %eax,%ecx
  40cf0a:	29 c6                	sub    %eax,%esi
  40cf0c:	29 c2                	sub    %eax,%edx
  40cf0e:	c1 e9 03             	shr    $0x3,%ecx
  40cf11:	31 f1                	xor    %esi,%ecx
  40cf13:	89 d6                	mov    %edx,%esi
  40cf15:	89 ca                	mov    %ecx,%edx
  40cf17:	29 ce                	sub    %ecx,%esi
  40cf19:	29 c8                	sub    %ecx,%eax
  40cf1b:	c1 e2 0a             	shl    $0xa,%edx
  40cf1e:	31 f2                	xor    %esi,%edx
  40cf20:	29 d0                	sub    %edx,%eax
  40cf22:	89 c6                	mov    %eax,%esi
  40cf24:	89 d0                	mov    %edx,%eax
  40cf26:	c1 e8 0f             	shr    $0xf,%eax
  40cf29:	31 f0                	xor    %esi,%eax
  40cf2b:	41 83 f8 0b          	cmp    $0xb,%r8d
  40cf2f:	0f 87 01 ff ff ff    	ja     40ce36 <process_udp.isra.0+0x276>
  40cf35:	44 01 c8             	add    %r9d,%eax
  40cf38:	41 83 f8 0b          	cmp    $0xb,%r8d
  40cf3c:	0f 87 62 21 00 00    	ja     40f0a4 <process_udp.isra.0+0x24e4>
  40cf42:	48 8d 35 0b 85 01 00 	lea    0x1850b(%rip),%rsi        # 425454 <ftbl+0xb4>
  40cf49:	4e 63 04 86          	movslq (%rsi,%r8,4),%r8
  40cf4d:	49 01 f0             	add    %rsi,%r8
  40cf50:	3e 41 ff e0          	notrack jmp *%r8
  40cf54:	4c 89 b5 c8 f0 ff ff 	mov    %r14,-0xf38(%rbp)
  40cf5b:	41 bf 02 00 00 00    	mov    $0x2,%r15d
  40cf61:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40cf68:	80 78 16 00          	cmpb   $0x0,0x16(%rax)
  40cf6c:	0f 84 6e 01 00 00    	je     40d0e0 <process_udp.isra.0+0x520>
  40cf72:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40cf79:	48 83 40 60 01       	addq   $0x1,0x60(%rax)
  40cf7e:	48 8b 85 c0 f0 ff ff 	mov    -0xf40(%rbp),%rax
  40cf85:	4c 8d a5 d8 f0 ff ff 	lea    -0xf28(%rbp),%r12
  40cf8c:	48 8b b5 b8 f0 ff ff 	mov    -0xf48(%rbp),%rsi
  40cf93:	48 8d 8d e0 f0 ff ff 	lea    -0xf20(%rbp),%rcx
  40cf9a:	4c 89 e2             	mov    %r12,%rdx
  40cf9d:	48 89 8d 90 f0 ff ff 	mov    %rcx,-0xf70(%rbp)
  40cfa4:	48 89 85 d8 f0 ff ff 	mov    %rax,-0xf28(%rbp)
  40cfab:	48 8d 85 20 f1 ff ff 	lea    -0xee0(%rbp),%rax
  40cfb2:	48 89 c7             	mov    %rax,%rdi
  40cfb5:	48 89 85 88 f0 ff ff 	mov    %rax,-0xf78(%rbp)
  40cfbc:	48 c7 85 e0 f0 ff ff 	movq   $0x0,-0xf20(%rbp)
  40cfc3:	00 00 00 00 
  40cfc7:	e8 04 c6 00 00       	call   4195d0 <decode_common>
  40cfcc:	85 c0                	test   %eax,%eax
  40cfce:	0f 88 32 3a 00 00    	js     410a06 <process_udp.isra.0+0x3e46>
  40cfd4:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40cfdb:	44 0f b6 85 21 f1 ff 	movzbl -0xedf(%rbp),%r8d
  40cfe2:	ff 
  40cfe3:	48 83 78 58 00       	cmpq   $0x0,0x58(%rax)
  40cfe8:	4c 89 c3             	mov    %r8,%rbx
  40cfeb:	74 1d                	je     40d00a <process_udp.isra.0+0x44a>
  40cfed:	8d 43 f9             	lea    -0x7(%rbx),%eax
  40cff0:	3c 01                	cmp    $0x1,%al
  40cff2:	0f 97 c2             	seta   %dl
  40cff5:	49 83 f8 05          	cmp    $0x5,%r8
  40cff9:	0f 95 c0             	setne  %al
  40cffc:	84 c2                	test   %al,%dl
  40cffe:	74 0a                	je     40d00a <process_udp.isra.0+0x44a>
  40d000:	41 83 ff 02          	cmp    $0x2,%r15d
  40d004:	0f 85 76 3e 00 00    	jne    410e80 <process_udp.isra.0+0x42c0>
  40d00a:	0f b6 85 22 f1 ff ff 	movzbl -0xede(%rbp),%eax
  40d011:	45 31 f6             	xor    %r14d,%r14d
  40d014:	83 e0 20             	and    $0x20,%eax
  40d017:	88 85 87 f0 ff ff    	mov    %al,-0xf79(%rbp)
  40d01d:	75 32                	jne    40d051 <process_udp.isra.0+0x491>
  40d01f:	0f b6 85 20 f1 ff ff 	movzbl -0xee0(%rbp),%eax
  40d026:	84 c0                	test   %al,%al
  40d028:	0f 84 61 17 00 00    	je     40e78f <process_udp.isra.0+0x1bcf>
  40d02e:	83 e8 01             	sub    $0x1,%eax
  40d031:	88 85 20 f1 ff ff    	mov    %al,-0xee0(%rbp)
  40d037:	80 fb 0b             	cmp    $0xb,%bl
  40d03a:	0f 87 e4 13 00 00    	ja     40e424 <process_udp.isra.0+0x1864>
  40d040:	48 8d 15 3d 84 01 00 	lea    0x1843d(%rip),%rdx        # 425484 <ftbl+0xe4>
  40d047:	4a 63 04 82          	movslq (%rdx,%r8,4),%rax
  40d04b:	48 01 d0             	add    %rdx,%rax
  40d04e:	3e ff e0             	notrack jmp *%rax
  40d051:	48 8b 85 98 f0 ff ff 	mov    -0xf68(%rbp),%rax
  40d058:	48 8b b5 b0 f0 ff ff 	mov    -0xf50(%rbp),%rsi
  40d05f:	48 8d 8d d0 f0 ff ff 	lea    -0xf30(%rbp),%rcx
  40d066:	48 8d 15 77 84 01 00 	lea    0x18477(%rip),%rdx        # 4254e4 <null_mac>
  40d06d:	4c 89 85 a0 f0 ff ff 	mov    %r8,-0xf60(%rbp)
  40d074:	48 8b 80 c0 00 00 00 	mov    0xc0(%rax),%rax
  40d07b:	c7 85 d0 f0 ff ff 01 	movl   $0x1,-0xf30(%rbp)
  40d082:	00 00 00 
  40d085:	48 8d 78 48          	lea    0x48(%rax),%rdi
  40d089:	48 89 85 a8 f0 ff ff 	mov    %rax,-0xf58(%rbp)
  40d090:	e8 6b 88 ff ff       	call   405900 <add_sn_to_list_by_mac_or_sock>
  40d095:	4c 8b 85 a0 f0 ff ff 	mov    -0xf60(%rbp),%r8
  40d09c:	48 85 c0             	test   %rax,%rax
  40d09f:	49 89 c6             	mov    %rax,%r14
  40d0a2:	0f 85 77 ff ff ff    	jne    40d01f <process_udp.isra.0+0x45f>
  40d0a8:	49 83 f8 05          	cmp    $0x5,%r8
  40d0ac:	0f 84 6d ff ff ff    	je     40d01f <process_udp.isra.0+0x45f>
  40d0b2:	48 8d 0d 9f 5e 01 00 	lea    0x15e9f(%rip),%rcx        # 422f58 <_IO_stdin_used+0x1f58>
  40d0b9:	ba a7 06 00 00       	mov    $0x6a7,%edx
  40d0be:	48 8d 35 30 78 01 00 	lea    0x17830(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40d0c5:	31 c0                	xor    %eax,%eax
  40d0c7:	bf 04 00 00 00       	mov    $0x4,%edi
  40d0cc:	e8 9f 72 ff ff       	call   404370 <_traceEvent>
  40d0d1:	e9 c9 fc ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40d0d6:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
  40d0dd:	00 00 00 
  40d0e0:	48 89 c3             	mov    %rax,%rbx
  40d0e3:	49 89 c0             	mov    %rax,%r8
  40d0e6:	48 8d 0d 5b 5d 01 00 	lea    0x15d5b(%rip),%rcx        # 422e48 <_IO_stdin_used+0x1e48>
  40d0ed:	31 c0                	xor    %eax,%eax
  40d0ef:	ba 6c 06 00 00       	mov    $0x66c,%edx
  40d0f4:	48 8d 35 fa 77 01 00 	lea    0x177fa(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40d0fb:	bf 03 00 00 00       	mov    $0x3,%edi
  40d100:	e8 6b 72 ff ff       	call   404370 <_traceEvent>
  40d105:	c6 43 16 02          	movb   $0x2,0x16(%rbx)
  40d109:	e9 64 fe ff ff       	jmp    40cf72 <process_udp.isra.0+0x3b2>
  40d10e:	4c 89 b5 c8 f0 ff ff 	mov    %r14,-0xf38(%rbp)
  40d115:	41 89 c7             	mov    %eax,%r15d
  40d118:	e9 44 fe ff ff       	jmp    40cf61 <process_udp.isra.0+0x3a1>
  40d11d:	48 83 bd c8 f0 ff ff 	cmpq   $0x0,-0xf38(%rbp)
  40d124:	00 
  40d125:	48 c7 85 f8 f0 ff ff 	movq   $0x0,-0xf08(%rbp)
  40d12c:	00 00 00 00 
  40d130:	c7 85 f0 f0 ff ff 00 	movl   $0x0,-0xf10(%rbp)
  40d137:	00 00 00 
  40d13a:	0f 84 07 19 00 00    	je     40ea47 <process_udp.isra.0+0x1e87>
  40d140:	48 8d 85 a0 f1 ff ff 	lea    -0xe60(%rbp),%rax
  40d147:	4c 8b 85 90 f0 ff ff 	mov    -0xf70(%rbp),%r8
  40d14e:	4c 89 e1             	mov    %r12,%rcx
  40d151:	48 8b 95 b8 f0 ff ff 	mov    -0xf48(%rbp),%rdx
  40d158:	48 8b b5 88 f0 ff ff 	mov    -0xf78(%rbp),%rsi
  40d15f:	48 89 c7             	mov    %rax,%rdi
  40d162:	48 89 85 50 f0 ff ff 	mov    %rax,-0xfb0(%rbp)
  40d169:	4c 8d bd a2 f1 ff ff 	lea    -0xe5e(%rbp),%r15
  40d170:	e8 9b e0 00 00       	call   41b210 <decode_QUERY_PEER>
  40d175:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40d17c:	80 78 16 02          	cmpb   $0x2,0x16(%rax)
  40d180:	0f 84 ab 30 00 00    	je     410231 <process_udp.isra.0+0x3671>
  40d186:	48 8d 9d bc f1 ff ff 	lea    -0xe44(%rbp),%rbx
  40d18d:	48 89 df             	mov    %rbx,%rdi
  40d190:	e8 ab 7a ff ff       	call   404c40 <is_null_mac>
  40d195:	84 c0                	test   %al,%al
  40d197:	0f 85 14 16 00 00    	jne    40e7b1 <process_udp.isra.0+0x1bf1>
  40d19d:	48 8d bd 30 f3 ff ff 	lea    -0xcd0(%rbp),%rdi
  40d1a4:	48 89 de             	mov    %rbx,%rsi
  40d1a7:	4c 8d a5 f0 f2 ff ff 	lea    -0xd10(%rbp),%r12
  40d1ae:	e8 4d 77 ff ff       	call   404900 <macaddr_str>
  40d1b3:	4c 89 fe             	mov    %r15,%rsi
  40d1b6:	4c 89 e7             	mov    %r12,%rdi
  40d1b9:	49 89 c5             	mov    %rax,%r13
  40d1bc:	e8 3f 77 ff ff       	call   404900 <macaddr_str>
  40d1c1:	4d 89 e9             	mov    %r13,%r9
  40d1c4:	48 8d 0d 86 79 01 00 	lea    0x17986(%rip),%rcx        # 424b51 <_IO_stdin_used+0x3b51>
  40d1cb:	ba 96 09 00 00       	mov    $0x996,%edx
  40d1d0:	49 89 c0             	mov    %rax,%r8
  40d1d3:	48 8d 35 1b 77 01 00 	lea    0x1771b(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40d1da:	31 c0                	xor    %eax,%eax
  40d1dc:	bf 04 00 00 00       	mov    $0x4,%edi
  40d1e1:	e8 8a 71 ff ff       	call   404370 <_traceEvent>
  40d1e6:	48 83 bd c8 f0 ff ff 	cmpq   $0x0,-0xf38(%rbp)
  40d1ed:	00 
  40d1ee:	0f 84 61 3c 00 00    	je     410e55 <process_udp.isra.0+0x4295>
  40d1f4:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40d1fb:	48 8b 70 48          	mov    0x48(%rax),%rsi
  40d1ff:	48 85 f6             	test   %rsi,%rsi
  40d202:	0f 84 6c 2b 00 00    	je     40fd74 <process_udp.isra.0+0x31b4>
  40d208:	0f b6 85 c1 f1 ff ff 	movzbl -0xe3f(%rbp),%eax
  40d20f:	0f b6 95 c0 f1 ff ff 	movzbl -0xe40(%rbp),%edx
  40d216:	c1 e0 08             	shl    $0x8,%eax
  40d219:	8d 8c 10 b9 79 37 9e 	lea    -0x61c88647(%rax,%rdx,1),%ecx
  40d220:	0f b6 85 bf f1 ff ff 	movzbl -0xe41(%rbp),%eax
  40d227:	0f b6 95 bc f1 ff ff 	movzbl -0xe44(%rbp),%edx
  40d22e:	c1 e0 18             	shl    $0x18,%eax
  40d231:	8d 84 10 c4 ba 49 9f 	lea    -0x60b6453c(%rax,%rdx,1),%eax
  40d238:	0f b6 95 be f1 ff ff 	movzbl -0xe42(%rbp),%edx
  40d23f:	c1 e2 10             	shl    $0x10,%edx
  40d242:	01 d0                	add    %edx,%eax
  40d244:	0f b6 95 bd f1 ff ff 	movzbl -0xe43(%rbp),%edx
  40d24b:	c1 e2 08             	shl    $0x8,%edx
  40d24e:	01 d0                	add    %edx,%eax
  40d250:	29 c8                	sub    %ecx,%eax
  40d252:	81 c1 0b 41 12 01    	add    $0x112410b,%ecx
  40d258:	35 6d f7 07 00       	xor    $0x7f76d,%eax
  40d25d:	29 c1                	sub    %eax,%ecx
  40d25f:	89 c2                	mov    %eax,%edx
  40d261:	c1 e0 08             	shl    $0x8,%eax
  40d264:	31 c8                	xor    %ecx,%eax
  40d266:	b9 f5 be ed fe       	mov    $0xfeedbef5,%ecx
  40d26b:	29 d1                	sub    %edx,%ecx
  40d26d:	89 c7                	mov    %eax,%edi
  40d26f:	29 c2                	sub    %eax,%edx
  40d271:	29 c1                	sub    %eax,%ecx
  40d273:	c1 ef 0d             	shr    $0xd,%edi
  40d276:	31 cf                	xor    %ecx,%edi
  40d278:	89 f9                	mov    %edi,%ecx
  40d27a:	29 fa                	sub    %edi,%edx
  40d27c:	29 f8                	sub    %edi,%eax
  40d27e:	c1 e9 0c             	shr    $0xc,%ecx
  40d281:	31 d1                	xor    %edx,%ecx
  40d283:	89 ca                	mov    %ecx,%edx
  40d285:	29 c8                	sub    %ecx,%eax
  40d287:	29 cf                	sub    %ecx,%edi
  40d289:	c1 e2 10             	shl    $0x10,%edx
  40d28c:	31 c2                	xor    %eax,%edx
  40d28e:	89 d0                	mov    %edx,%eax
  40d290:	29 d7                	sub    %edx,%edi
  40d292:	29 d1                	sub    %edx,%ecx
  40d294:	c1 e8 05             	shr    $0x5,%eax
  40d297:	31 f8                	xor    %edi,%eax
  40d299:	89 c7                	mov    %eax,%edi
  40d29b:	29 c1                	sub    %eax,%ecx
  40d29d:	c1 ef 03             	shr    $0x3,%edi
  40d2a0:	31 f9                	xor    %edi,%ecx
  40d2a2:	29 c2                	sub    %eax,%edx
  40d2a4:	89 cf                	mov    %ecx,%edi
  40d2a6:	29 ca                	sub    %ecx,%edx
  40d2a8:	29 c8                	sub    %ecx,%eax
  40d2aa:	48 8b 8e e8 00 00 00 	mov    0xe8(%rsi),%rcx
  40d2b1:	c1 e7 0a             	shl    $0xa,%edi
  40d2b4:	31 fa                	xor    %edi,%edx
  40d2b6:	29 d0                	sub    %edx,%eax
  40d2b8:	c1 ea 0f             	shr    $0xf,%edx
  40d2bb:	31 c2                	xor    %eax,%edx
  40d2bd:	8b 41 08             	mov    0x8(%rcx),%eax
  40d2c0:	83 e8 01             	sub    $0x1,%eax
  40d2c3:	21 d0                	and    %edx,%eax
  40d2c5:	48 c1 e0 04          	shl    $0x4,%rax
  40d2c9:	48 03 01             	add    (%rcx),%rax
  40d2cc:	48 8b 00             	mov    (%rax),%rax
  40d2cf:	48 85 c0             	test   %rax,%rax
  40d2d2:	0f 84 9c 2a 00 00    	je     40fd74 <process_udp.isra.0+0x31b4>
  40d2d8:	48 8b 71 20          	mov    0x20(%rcx),%rsi
  40d2dc:	48 89 f1             	mov    %rsi,%rcx
  40d2df:	48 29 f0             	sub    %rsi,%rax
  40d2e2:	48 f7 d9             	neg    %rcx
  40d2e5:	eb 1c                	jmp    40d303 <process_udp.isra.0+0x743>
  40d2e7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
  40d2ee:	00 00 
  40d2f0:	48 8b 80 08 01 00 00 	mov    0x108(%rax),%rax
  40d2f7:	48 85 c0             	test   %rax,%rax
  40d2fa:	0f 84 74 2a 00 00    	je     40fd74 <process_udp.isra.0+0x31b4>
  40d300:	48 01 c8             	add    %rcx,%rax
  40d303:	3b 90 1c 01 00 00    	cmp    0x11c(%rax),%edx
  40d309:	75 e5                	jne    40d2f0 <process_udp.isra.0+0x730>
  40d30b:	83 b8 18 01 00 00 06 	cmpl   $0x6,0x118(%rax)
  40d312:	75 dc                	jne    40d2f0 <process_udp.isra.0+0x730>
  40d314:	48 8b b0 10 01 00 00 	mov    0x110(%rax),%rsi
  40d31b:	8b 3b                	mov    (%rbx),%edi
  40d31d:	39 3e                	cmp    %edi,(%rsi)
  40d31f:	75 cf                	jne    40d2f0 <process_udp.isra.0+0x730>
  40d321:	0f b7 7b 04          	movzwl 0x4(%rbx),%edi
  40d325:	66 39 7e 04          	cmp    %di,0x4(%rsi)
  40d329:	75 c5                	jne    40d2f0 <process_udp.isra.0+0x730>
  40d32b:	8b 95 34 f1 ff ff    	mov    -0xecc(%rbp),%edx
  40d331:	f3 0f 6f b5 24 f1 ff 	movdqu -0xedc(%rbp),%xmm6
  40d338:	ff 
  40d339:	45 31 d2             	xor    %r10d,%r10d
  40d33c:	c7 85 60 f1 ff ff 02 	movl   $0x200a02,-0xea0(%rbp)
  40d343:	0a 20 00 
  40d346:	66 44 89 95 10 f2 ff 	mov    %r10w,-0xdf0(%rbp)
  40d34d:	ff 
  40d34e:	89 95 74 f1 ff ff    	mov    %edx,-0xe8c(%rbp)
  40d354:	8b 95 a2 f1 ff ff    	mov    -0xe5e(%rbp),%edx
  40d35a:	0f 11 b5 64 f1 ff ff 	movups %xmm6,-0xe9c(%rbp)
  40d361:	89 95 12 f2 ff ff    	mov    %edx,-0xdee(%rbp)
  40d367:	0f b7 95 a6 f1 ff ff 	movzwl -0xe5a(%rbp),%edx
  40d36e:	66 89 95 16 f2 ff ff 	mov    %dx,-0xdea(%rbp)
  40d375:	8b 95 bc f1 ff ff    	mov    -0xe44(%rbp),%edx
  40d37b:	89 95 18 f2 ff ff    	mov    %edx,-0xde8(%rbp)
  40d381:	0f b7 95 c0 f1 ff ff 	movzwl -0xe40(%rbp),%edx
  40d388:	66 89 95 1c f2 ff ff 	mov    %dx,-0xde4(%rbp)
  40d38f:	f3 0f 6f 78 20       	movdqu 0x20(%rax),%xmm7
  40d394:	8b 50 30             	mov    0x30(%rax),%edx
  40d397:	0f 11 bd 1e f2 ff ff 	movups %xmm7,-0xde2(%rbp)
  40d39e:	89 95 2e f2 ff ff    	mov    %edx,-0xdd2(%rbp)
  40d3a4:	80 78 38 ff          	cmpb   $0xff,0x38(%rax)
  40d3a8:	74 23                	je     40d3cd <process_udp.isra.0+0x80d>
  40d3aa:	f3 0f 6f 48 38       	movdqu 0x38(%rax),%xmm1
  40d3af:	8b 40 48             	mov    0x48(%rax),%eax
  40d3b2:	41 b9 60 00 00 00    	mov    $0x60,%r9d
  40d3b8:	66 44 89 8d 62 f1 ff 	mov    %r9w,-0xe9e(%rbp)
  40d3bf:	ff 
  40d3c0:	89 85 42 f2 ff ff    	mov    %eax,-0xdbe(%rbp)
  40d3c6:	0f 11 8d 32 f2 ff ff 	movups %xmm1,-0xdce(%rbp)
  40d3cd:	48 8d 85 c0 f7 ff ff 	lea    -0x840(%rbp),%rax
  40d3d4:	48 8d 8d 10 f2 ff ff 	lea    -0xdf0(%rbp),%rcx
  40d3db:	48 8d 95 60 f1 ff ff 	lea    -0xea0(%rbp),%rdx
  40d3e2:	48 8d b5 f8 f0 ff ff 	lea    -0xf08(%rbp),%rsi
  40d3e9:	48 89 c7             	mov    %rax,%rdi
  40d3ec:	48 89 85 c0 f0 ff ff 	mov    %rax,-0xf40(%rbp)
  40d3f3:	e8 78 da 00 00       	call   41ae70 <encode_PEER_INFO>
  40d3f8:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40d3ff:	80 78 16 02          	cmpb   $0x2,0x16(%rax)
  40d403:	0f 84 e5 38 00 00    	je     410cee <process_udp.isra.0+0x412e>
  40d409:	4c 8b 85 f8 f0 ff ff 	mov    -0xf08(%rbp),%r8
  40d410:	48 8b 8d c0 f0 ff ff 	mov    -0xf40(%rbp),%rcx
  40d417:	48 8b 95 78 f0 ff ff 	mov    -0xf88(%rbp),%rdx
  40d41e:	8b b5 80 f0 ff ff    	mov    -0xf80(%rbp),%esi
  40d424:	48 8b bd 98 f0 ff ff 	mov    -0xf68(%rbp),%rdi
  40d42b:	e8 10 bb ff ff       	call   408f40 <sendto_sock>
  40d430:	4c 89 fe             	mov    %r15,%rsi
  40d433:	4c 89 e7             	mov    %r12,%rdi
  40d436:	e8 c5 74 ff ff       	call   404900 <macaddr_str>
  40d43b:	ba bc 09 00 00       	mov    $0x9bc,%edx
  40d440:	bf 04 00 00 00       	mov    $0x4,%edi
  40d445:	48 8d 0d 22 77 01 00 	lea    0x17722(%rip),%rcx        # 424b6e <_IO_stdin_used+0x3b6e>
  40d44c:	49 89 c0             	mov    %rax,%r8
  40d44f:	48 8d 35 9f 74 01 00 	lea    0x1749f(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40d456:	31 c0                	xor    %eax,%eax
  40d458:	e8 13 6f ff ff       	call   404370 <_traceEvent>
  40d45d:	e9 3d f9 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40d462:	48 83 bd c8 f0 ff ff 	cmpq   $0x0,-0xf38(%rbp)
  40d469:	00 
  40d46a:	48 c7 85 f8 f0 ff ff 	movq   $0x0,-0xf08(%rbp)
  40d471:	00 00 00 00 
  40d475:	0f 84 68 3a 00 00    	je     410ee3 <process_udp.isra.0+0x4323>
  40d47b:	48 8d 85 10 f2 ff ff 	lea    -0xdf0(%rbp),%rax
  40d482:	4c 8b 85 90 f0 ff ff 	mov    -0xf70(%rbp),%r8
  40d489:	4c 89 e1             	mov    %r12,%rcx
  40d48c:	48 8b 95 b8 f0 ff ff 	mov    -0xf48(%rbp),%rdx
  40d493:	48 8b b5 88 f0 ff ff 	mov    -0xf78(%rbp),%rsi
  40d49a:	48 89 c7             	mov    %rax,%rdi
  40d49d:	48 89 85 60 f0 ff ff 	mov    %rax,-0xfa0(%rbp)
  40d4a4:	48 8d 9d 12 f2 ff ff 	lea    -0xdee(%rbp),%rbx
  40d4ab:	e8 10 db 00 00       	call   41afc0 <decode_PEER_INFO>
  40d4b0:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40d4b7:	80 78 16 02          	cmpb   $0x2,0x16(%rax)
  40d4bb:	0f 84 0f 23 00 00    	je     40f7d0 <process_udp.isra.0+0x2c10>
  40d4c1:	48 8b b5 b0 f0 ff ff 	mov    -0xf50(%rbp),%rsi
  40d4c8:	48 8b bd 70 f0 ff ff 	mov    -0xf90(%rbp),%rdi
  40d4cf:	e8 9c 80 ff ff       	call   405570 <sock_to_cstr>
  40d4d4:	48 8d bd f0 f2 ff ff 	lea    -0xd10(%rbp),%rdi
  40d4db:	48 89 de             	mov    %rbx,%rsi
  40d4de:	49 89 c4             	mov    %rax,%r12
  40d4e1:	e8 1a 74 ff ff       	call   404900 <macaddr_str>
  40d4e6:	48 8d 35 08 74 01 00 	lea    0x17408(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40d4ed:	4d 89 e1             	mov    %r12,%r9
  40d4f0:	48 8d 0d 8a 76 01 00 	lea    0x1768a(%rip),%rcx        # 424b81 <_IO_stdin_used+0x3b81>
  40d4f7:	49 89 c0             	mov    %rax,%r8
  40d4fa:	ba ee 09 00 00       	mov    $0x9ee,%edx
  40d4ff:	31 c0                	xor    %eax,%eax
  40d501:	bf 03 00 00 00       	mov    $0x3,%edi
  40d506:	e8 65 6e ff ff       	call   404370 <_traceEvent>
  40d50b:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40d512:	48 8b 70 48          	mov    0x48(%rax),%rsi
  40d516:	48 85 f6             	test   %rsi,%rsi
  40d519:	0f 84 80 f8 ff ff    	je     40cd9f <process_udp.isra.0+0x1df>
  40d51f:	0f b6 85 17 f2 ff ff 	movzbl -0xde9(%rbp),%eax
  40d526:	0f b6 95 16 f2 ff ff 	movzbl -0xdea(%rbp),%edx
  40d52d:	bf f5 be ed fe       	mov    $0xfeedbef5,%edi
  40d532:	0f b6 8d 12 f2 ff ff 	movzbl -0xdee(%rbp),%ecx
  40d539:	c1 e0 08             	shl    $0x8,%eax
  40d53c:	8d 94 10 b9 79 37 9e 	lea    -0x61c88647(%rax,%rdx,1),%edx
  40d543:	0f b6 85 15 f2 ff ff 	movzbl -0xdeb(%rbp),%eax
  40d54a:	c1 e0 18             	shl    $0x18,%eax
  40d54d:	8d 84 08 c4 ba 49 9f 	lea    -0x60b6453c(%rax,%rcx,1),%eax
  40d554:	0f b6 8d 14 f2 ff ff 	movzbl -0xdec(%rbp),%ecx
  40d55b:	c1 e1 10             	shl    $0x10,%ecx
  40d55e:	01 c8                	add    %ecx,%eax
  40d560:	0f b6 8d 13 f2 ff ff 	movzbl -0xded(%rbp),%ecx
  40d567:	c1 e1 08             	shl    $0x8,%ecx
  40d56a:	01 c8                	add    %ecx,%eax
  40d56c:	29 d0                	sub    %edx,%eax
  40d56e:	81 c2 0b 41 12 01    	add    $0x112410b,%edx
  40d574:	35 6d f7 07 00       	xor    $0x7f76d,%eax
  40d579:	89 c1                	mov    %eax,%ecx
  40d57b:	29 c2                	sub    %eax,%edx
  40d57d:	c1 e0 08             	shl    $0x8,%eax
  40d580:	31 c2                	xor    %eax,%edx
  40d582:	29 cf                	sub    %ecx,%edi
  40d584:	89 d0                	mov    %edx,%eax
  40d586:	29 d7                	sub    %edx,%edi
  40d588:	29 d1                	sub    %edx,%ecx
  40d58a:	c1 e8 0d             	shr    $0xd,%eax
  40d58d:	31 f8                	xor    %edi,%eax
  40d58f:	89 c7                	mov    %eax,%edi
  40d591:	29 c1                	sub    %eax,%ecx
  40d593:	29 c2                	sub    %eax,%edx
  40d595:	c1 ef 0c             	shr    $0xc,%edi
  40d598:	31 f9                	xor    %edi,%ecx
  40d59a:	89 cf                	mov    %ecx,%edi
  40d59c:	29 ca                	sub    %ecx,%edx
  40d59e:	29 c8                	sub    %ecx,%eax
  40d5a0:	c1 e7 10             	shl    $0x10,%edi
  40d5a3:	31 fa                	xor    %edi,%edx
  40d5a5:	89 d7                	mov    %edx,%edi
  40d5a7:	29 d0                	sub    %edx,%eax
  40d5a9:	29 d1                	sub    %edx,%ecx
  40d5ab:	c1 ef 05             	shr    $0x5,%edi
  40d5ae:	31 f8                	xor    %edi,%eax
  40d5b0:	89 c7                	mov    %eax,%edi
  40d5b2:	29 c1                	sub    %eax,%ecx
  40d5b4:	c1 ef 03             	shr    $0x3,%edi
  40d5b7:	31 cf                	xor    %ecx,%edi
  40d5b9:	29 c2                	sub    %eax,%edx
  40d5bb:	89 f9                	mov    %edi,%ecx
  40d5bd:	29 fa                	sub    %edi,%edx
  40d5bf:	29 f8                	sub    %edi,%eax
  40d5c1:	c1 e1 0a             	shl    $0xa,%ecx
  40d5c4:	31 ca                	xor    %ecx,%edx
  40d5c6:	48 8b 8e e8 00 00 00 	mov    0xe8(%rsi),%rcx
  40d5cd:	29 d0                	sub    %edx,%eax
  40d5cf:	c1 ea 0f             	shr    $0xf,%edx
  40d5d2:	31 c2                	xor    %eax,%edx
  40d5d4:	8b 41 08             	mov    0x8(%rcx),%eax
  40d5d7:	83 e8 01             	sub    $0x1,%eax
  40d5da:	21 d0                	and    %edx,%eax
  40d5dc:	48 c1 e0 04          	shl    $0x4,%rax
  40d5e0:	48 03 01             	add    (%rcx),%rax
  40d5e3:	48 8b 00             	mov    (%rax),%rax
  40d5e6:	48 85 c0             	test   %rax,%rax
  40d5e9:	0f 84 b0 f7 ff ff    	je     40cd9f <process_udp.isra.0+0x1df>
  40d5ef:	48 8b 71 20          	mov    0x20(%rcx),%rsi
  40d5f3:	48 89 f1             	mov    %rsi,%rcx
  40d5f6:	48 29 f0             	sub    %rsi,%rax
  40d5f9:	48 f7 d9             	neg    %rcx
  40d5fc:	49 89 c4             	mov    %rax,%r12
  40d5ff:	eb 1b                	jmp    40d61c <process_udp.isra.0+0xa5c>
  40d601:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  40d608:	4d 8b a4 24 08 01 00 	mov    0x108(%r12),%r12
  40d60f:	00 
  40d610:	4d 85 e4             	test   %r12,%r12
  40d613:	0f 84 86 f7 ff ff    	je     40cd9f <process_udp.isra.0+0x1df>
  40d619:	49 01 cc             	add    %rcx,%r12
  40d61c:	41 3b 94 24 1c 01 00 	cmp    0x11c(%r12),%edx
  40d623:	00 
  40d624:	75 e2                	jne    40d608 <process_udp.isra.0+0xa48>
  40d626:	41 83 bc 24 18 01 00 	cmpl   $0x6,0x118(%r12)
  40d62d:	00 06 
  40d62f:	75 d7                	jne    40d608 <process_udp.isra.0+0xa48>
  40d631:	49 8b 84 24 10 01 00 	mov    0x110(%r12),%rax
  40d638:	00 
  40d639:	8b 33                	mov    (%rbx),%esi
  40d63b:	39 30                	cmp    %esi,(%rax)
  40d63d:	75 c9                	jne    40d608 <process_udp.isra.0+0xa48>
  40d63f:	0f b7 73 04          	movzwl 0x4(%rbx),%esi
  40d643:	66 39 70 04          	cmp    %si,0x4(%rax)
  40d647:	75 bf                	jne    40d608 <process_udp.isra.0+0xa48>
  40d649:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40d650:	80 78 14 00          	cmpb   $0x0,0x14(%rax)
  40d654:	0f 85 45 f7 ff ff    	jne    40cd9f <process_udp.isra.0+0x1df>
  40d65a:	48 89 df             	mov    %rbx,%rdi
  40d65d:	e8 de 75 ff ff       	call   404c40 <is_null_mac>
  40d662:	84 c0                	test   %al,%al
  40d664:	0f 85 35 f7 ff ff    	jne    40cd9f <process_udp.isra.0+0x1df>
  40d66a:	48 8b 9d c8 f0 ff ff 	mov    -0xf38(%rbp),%rbx
  40d671:	4c 8b 45 10          	mov    0x10(%rbp),%r8
  40d675:	48 8d b5 18 f2 ff ff 	lea    -0xde8(%rbp),%rsi
  40d67c:	8b 8d 6c f0 ff ff    	mov    -0xf94(%rbp),%ecx
  40d682:	48 8b 95 78 f0 ff ff 	mov    -0xf88(%rbp),%rdx
  40d689:	48 89 df             	mov    %rbx,%rdi
  40d68c:	e8 6f d2 ff ff       	call   40a900 <update_node_supernode_association>
  40d691:	48 8d 85 c0 f7 ff ff 	lea    -0x840(%rbp),%rax
  40d698:	48 8b 8d 60 f0 ff ff 	mov    -0xfa0(%rbp),%rcx
  40d69f:	48 8b 95 88 f0 ff ff 	mov    -0xf78(%rbp),%rdx
  40d6a6:	48 8d b5 f8 f0 ff ff 	lea    -0xf08(%rbp),%rsi
  40d6ad:	48 89 c7             	mov    %rax,%rdi
  40d6b0:	48 89 85 c0 f0 ff ff 	mov    %rax,-0xf40(%rbp)
  40d6b7:	e8 b4 d7 00 00       	call   41ae70 <encode_PEER_INFO>
  40d6bc:	80 7b 16 02          	cmpb   $0x2,0x16(%rbx)
  40d6c0:	0f 84 73 38 00 00    	je     410f39 <process_udp.isra.0+0x4379>
  40d6c6:	48 8b 8d f8 f0 ff ff 	mov    -0xf08(%rbp),%rcx
  40d6cd:	48 8b 95 c0 f0 ff ff 	mov    -0xf40(%rbp),%rdx
  40d6d4:	4c 89 e6             	mov    %r12,%rsi
  40d6d7:	48 8b bd 98 f0 ff ff 	mov    -0xf68(%rbp),%rdi
  40d6de:	e8 9d b9 ff ff       	call   409080 <sendto_peer>
  40d6e3:	e9 b7 f6 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40d6e8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  40d6ef:	00 
  40d6f0:	4c 8d 9d 10 f2 ff ff 	lea    -0xdf0(%rbp),%r11
  40d6f7:	31 c0                	xor    %eax,%eax
  40d6f9:	b9 0c 00 00 00       	mov    $0xc,%ecx
  40d6fe:	48 83 bd c8 f0 ff ff 	cmpq   $0x0,-0xf38(%rbp)
  40d705:	00 
  40d706:	4c 89 df             	mov    %r11,%rdi
  40d709:	f3 48 ab             	rep stos %rax,%es:(%rdi)
  40d70c:	c7 07 00 00 00 00    	movl   $0x0,(%rdi)
  40d712:	0f 84 28 39 00 00    	je     411040 <process_udp.isra.0+0x4480>
  40d718:	80 bd 87 f0 ff ff 00 	cmpb   $0x0,-0xf79(%rbp)
  40d71f:	0f 84 30 35 00 00    	je     410c55 <process_udp.isra.0+0x4095>
  40d725:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40d72c:	80 78 14 00          	cmpb   $0x0,0x14(%rax)
  40d730:	0f 84 1f 35 00 00    	je     410c55 <process_udp.isra.0+0x4095>
  40d736:	48 8d 85 c0 f7 ff ff 	lea    -0x840(%rbp),%rax
  40d73d:	4c 89 e1             	mov    %r12,%rcx
  40d740:	4c 89 df             	mov    %r11,%rdi
  40d743:	4c 8b 85 90 f0 ff ff 	mov    -0xf70(%rbp),%r8
  40d74a:	48 8b 95 b8 f0 ff ff 	mov    -0xf48(%rbp),%rdx
  40d751:	48 8b b5 88 f0 ff ff 	mov    -0xf78(%rbp),%rsi
  40d758:	49 89 c1             	mov    %rax,%r9
  40d75b:	48 89 85 c0 f0 ff ff 	mov    %rax,-0xf40(%rbp)
  40d762:	4c 8d bd 14 f2 ff ff 	lea    -0xdec(%rbp),%r15
  40d769:	e8 02 cf 00 00       	call   41a670 <decode_REGISTER_SUPER_ACK>
  40d76e:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40d775:	80 78 16 02          	cmpb   $0x2,0x16(%rax)
  40d779:	0f 84 99 20 00 00    	je     40f818 <process_udp.isra.0+0x2c58>
  40d77f:	48 8d b5 26 f2 ff ff 	lea    -0xdda(%rbp),%rsi
  40d786:	48 8d bd 30 f3 ff ff 	lea    -0xcd0(%rbp),%rdi
  40d78d:	e8 de 7d ff ff       	call   405570 <sock_to_cstr>
  40d792:	4c 8b ad b0 f0 ff ff 	mov    -0xf50(%rbp),%r13
  40d799:	48 8d bd f0 f2 ff ff 	lea    -0xd10(%rbp),%rdi
  40d7a0:	49 89 c6             	mov    %rax,%r14
  40d7a3:	4c 89 ee             	mov    %r13,%rsi
  40d7a6:	e8 c5 7d ff ff       	call   405570 <sock_to_cstr>
  40d7ab:	4c 89 fe             	mov    %r15,%rsi
  40d7ae:	48 8d bd 90 f2 ff ff 	lea    -0xd70(%rbp),%rdi
  40d7b5:	48 89 c3             	mov    %rax,%rbx
  40d7b8:	e8 43 71 ff ff       	call   404900 <macaddr_str>
  40d7bd:	48 83 ec 08          	sub    $0x8,%rsp
  40d7c1:	49 89 d9             	mov    %rbx,%r9
  40d7c4:	48 8d 0d 9d 5b 01 00 	lea    0x15b9d(%rip),%rcx        # 423368 <_IO_stdin_used+0x2368>
  40d7cb:	41 56                	push   %r14
  40d7cd:	49 89 c0             	mov    %rax,%r8
  40d7d0:	ba cb 08 00 00       	mov    $0x8cb,%edx
  40d7d5:	bf 03 00 00 00       	mov    $0x3,%edi
  40d7da:	48 8d 35 14 71 01 00 	lea    0x17114(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40d7e1:	31 c0                	xor    %eax,%eax
  40d7e3:	48 8d 9d d0 f0 ff ff 	lea    -0xf30(%rbp),%rbx
  40d7ea:	e8 81 6b ff ff       	call   404370 <_traceEvent>
  40d7ef:	4c 89 fa             	mov    %r15,%rdx
  40d7f2:	48 89 d9             	mov    %rbx,%rcx
  40d7f5:	4c 89 ee             	mov    %r13,%rsi
  40d7f8:	48 8b 85 98 f0 ff ff 	mov    -0xf68(%rbp),%rax
  40d7ff:	c7 85 d0 f0 ff ff 01 	movl   $0x1,-0xf30(%rbp)
  40d806:	00 00 00 
  40d809:	48 8b 80 c0 00 00 00 	mov    0xc0(%rax),%rax
  40d810:	48 8d 78 48          	lea    0x48(%rax),%rdi
  40d814:	48 89 85 c8 f0 ff ff 	mov    %rax,-0xf38(%rbp)
  40d81b:	e8 e0 80 ff ff       	call   405900 <add_sn_to_list_by_mac_or_sock>
  40d820:	41 5e                	pop    %r14
  40d822:	41 5f                	pop    %r15
  40d824:	48 85 c0             	test   %rax,%rax
  40d827:	0f 84 e2 28 00 00    	je     41010f <process_udp.isra.0+0x354f>
  40d82d:	48 8b 75 10          	mov    0x10(%rbp),%rsi
  40d831:	48 89 b0 90 00 00 00 	mov    %rsi,0x90(%rax)
  40d838:	8b 40 4c             	mov    0x4c(%rax),%eax
  40d83b:	39 85 10 f2 ff ff    	cmp    %eax,-0xdf0(%rbp)
  40d841:	0f 85 80 12 00 00    	jne    40eac7 <process_udp.isra.0+0x1f07>
  40d847:	45 31 ff             	xor    %r15d,%r15d
  40d84a:	48 8d 85 a0 f1 ff ff 	lea    -0xe60(%rbp),%rax
  40d851:	80 bd 6e f2 ff ff 00 	cmpb   $0x0,-0xd92(%rbp)
  40d858:	4c 8b ad c0 f0 ff ff 	mov    -0xf40(%rbp),%r13
  40d85f:	48 89 85 50 f0 ff ff 	mov    %rax,-0xfb0(%rbp)
  40d866:	4c 8d 76 c4          	lea    -0x3c(%rsi),%r14
  40d86a:	0f 84 a7 00 00 00    	je     40d917 <process_udp.isra.0+0xd57>
  40d870:	48 89 9d c8 f0 ff ff 	mov    %rbx,-0xf38(%rbp)
  40d877:	48 8b 9d 98 f0 ff ff 	mov    -0xf68(%rbp),%rbx
  40d87e:	4c 89 b5 c0 f0 ff ff 	mov    %r14,-0xf40(%rbp)
  40d885:	4d 89 e6             	mov    %r12,%r14
  40d888:	4c 8b a5 50 f0 ff ff 	mov    -0xfb0(%rbp),%r12
  40d88f:	48 8b 8d 90 f0 ff ff 	mov    -0xf70(%rbp),%rcx
  40d896:	4c 89 f2             	mov    %r14,%rdx
  40d899:	4c 89 ee             	mov    %r13,%rsi
  40d89c:	4c 89 e7             	mov    %r12,%rdi
  40d89f:	c7 85 d0 f0 ff ff 00 	movl   $0x0,-0xf30(%rbp)
  40d8a6:	00 00 00 
  40d8a9:	48 c7 85 e0 f0 ff ff 	movq   $0x0,-0xf20(%rbp)
  40d8b0:	00 00 00 00 
  40d8b4:	48 c7 85 d8 f0 ff ff 	movq   $0x14,-0xf28(%rbp)
  40d8bb:	14 00 00 00 
  40d8bf:	e8 3c c0 00 00       	call   419900 <decode_sock_payload>
  40d8c4:	48 8b 83 c0 00 00 00 	mov    0xc0(%rbx),%rax
  40d8cb:	49 8d 55 14          	lea    0x14(%r13),%rdx
  40d8cf:	4c 89 e6             	mov    %r12,%rsi
  40d8d2:	48 8b 8d c8 f0 ff ff 	mov    -0xf38(%rbp),%rcx
  40d8d9:	48 8d 78 48          	lea    0x48(%rax),%rdi
  40d8dd:	e8 1e 80 ff ff       	call   405900 <add_sn_to_list_by_mac_or_sock>
  40d8e2:	8b 53 74             	mov    0x74(%rbx),%edx
  40d8e5:	83 bd d0 f0 ff ff 02 	cmpl   $0x2,-0xf30(%rbp)
  40d8ec:	89 50 34             	mov    %edx,0x34(%rax)
  40d8ef:	75 0e                	jne    40d8ff <process_udp.isra.0+0xd3f>
  40d8f1:	48 8b b5 c0 f0 ff ff 	mov    -0xf40(%rbp),%rsi
  40d8f8:	48 89 b0 90 00 00 00 	mov    %rsi,0x90(%rax)
  40d8ff:	0f b6 85 6e f2 ff ff 	movzbl -0xd92(%rbp),%eax
  40d906:	41 83 c7 01          	add    $0x1,%r15d
  40d90a:	49 83 c5 1a          	add    $0x1a,%r13
  40d90e:	41 39 c7             	cmp    %eax,%r15d
  40d911:	0f 8c 78 ff ff ff    	jl     40d88f <process_udp.isra.0+0xccf>
  40d917:	48 8b 85 98 f0 ff ff 	mov    -0xf68(%rbp),%rax
  40d91e:	8b b5 70 f2 ff ff    	mov    -0xd90(%rbp),%esi
  40d924:	39 b0 1c 01 00 00    	cmp    %esi,0x11c(%rax)
  40d92a:	0f 83 6f f4 ff ff    	jae    40cd9f <process_udp.isra.0+0x1df>
  40d930:	48 8d 0d cb 71 01 00 	lea    0x171cb(%rip),%rcx        # 424b02 <_IO_stdin_used+0x3b02>
  40d937:	ba f2 08 00 00       	mov    $0x8f2,%edx
  40d93c:	48 8d 35 b2 6f 01 00 	lea    0x16fb2(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40d943:	31 c0                	xor    %eax,%eax
  40d945:	bf 04 00 00 00       	mov    $0x4,%edi
  40d94a:	e8 21 6a ff ff       	call   404370 <_traceEvent>
  40d94f:	48 8b 9d 98 f0 ff ff 	mov    -0xf68(%rbp),%rbx
  40d956:	48 89 df             	mov    %rbx,%rdi
  40d959:	e8 b2 c4 ff ff       	call   409e10 <send_re_register_super>
  40d95e:	8b 85 70 f2 ff ff    	mov    -0xd90(%rbp),%eax
  40d964:	48 89 df             	mov    %rbx,%rdi
  40d967:	89 83 1c 01 00 00    	mov    %eax,0x11c(%rbx)
  40d96d:	e8 be c3 ff ff       	call   409d30 <calculate_dynamic_keys>
  40d972:	48 8b b3 c0 00 00 00 	mov    0xc0(%rbx),%rsi
  40d979:	48 8b 55 10          	mov    0x10(%rbp),%rdx
  40d97d:	48 89 df             	mov    %rbx,%rdi
  40d980:	b9 01 00 00 00       	mov    $0x1,%ecx
  40d985:	e8 e6 b7 ff ff       	call   409170 <re_register_and_purge_supernodes.part.0>
  40d98a:	e9 10 f4 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40d98f:	66 0f ef c0          	pxor   %xmm0,%xmm0
  40d993:	48 8d 85 10 f2 ff ff 	lea    -0xdf0(%rbp),%rax
  40d99a:	48 83 bd c8 f0 ff ff 	cmpq   $0x0,-0xf38(%rbp)
  40d9a1:	00 
  40d9a2:	0f 29 85 30 f2 ff ff 	movaps %xmm0,-0xdd0(%rbp)
  40d9a9:	48 89 85 60 f0 ff ff 	mov    %rax,-0xfa0(%rbp)
  40d9b0:	0f 29 85 10 f2 ff ff 	movaps %xmm0,-0xdf0(%rbp)
  40d9b7:	0f 29 85 20 f2 ff ff 	movaps %xmm0,-0xde0(%rbp)
  40d9be:	0f 11 85 3a f2 ff ff 	movups %xmm0,-0xdc6(%rbp)
  40d9c5:	0f 84 34 34 00 00    	je     410dff <process_udp.isra.0+0x423f>
  40d9cb:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40d9d2:	80 78 14 01          	cmpb   $0x1,0x14(%rax)
  40d9d6:	0f 84 15 36 00 00    	je     410ff1 <process_udp.isra.0+0x4431>
  40d9dc:	4c 8b 85 90 f0 ff ff 	mov    -0xf70(%rbp),%r8
  40d9e3:	48 8b 95 b8 f0 ff ff 	mov    -0xf48(%rbp),%rdx
  40d9ea:	4c 89 e1             	mov    %r12,%rcx
  40d9ed:	4c 8d a5 44 f2 ff ff 	lea    -0xdbc(%rbp),%r12
  40d9f4:	48 8b b5 88 f0 ff ff 	mov    -0xf78(%rbp),%rsi
  40d9fb:	48 8b bd 60 f0 ff ff 	mov    -0xfa0(%rbp),%rdi
  40da02:	e8 39 c7 00 00       	call   41a140 <decode_UNREGISTER_SUPER>
  40da07:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40da0e:	80 78 16 02          	cmpb   $0x2,0x16(%rax)
  40da12:	0f 84 89 1e 00 00    	je     40f8a1 <process_udp.isra.0+0x2ce1>
  40da18:	48 8d bd f0 f2 ff ff 	lea    -0xd10(%rbp),%rdi
  40da1f:	4c 89 e6             	mov    %r12,%rsi
  40da22:	e8 d9 6e ff ff       	call   404900 <macaddr_str>
  40da27:	ba 97 08 00 00       	mov    $0x897,%edx
  40da2c:	bf 04 00 00 00       	mov    $0x4,%edi
  40da31:	48 8d 35 bd 6e 01 00 	lea    0x16ebd(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40da38:	49 89 c0             	mov    %rax,%r8
  40da3b:	48 8d 0d d5 70 01 00 	lea    0x170d5(%rip),%rcx        # 424b17 <_IO_stdin_used+0x3b17>
  40da42:	31 c0                	xor    %eax,%eax
  40da44:	e8 27 69 ff ff       	call   404370 <_traceEvent>
  40da49:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40da50:	48 8b 70 48          	mov    0x48(%rax),%rsi
  40da54:	48 85 f6             	test   %rsi,%rsi
  40da57:	0f 84 42 f3 ff ff    	je     40cd9f <process_udp.isra.0+0x1df>
  40da5d:	0f b6 85 49 f2 ff ff 	movzbl -0xdb7(%rbp),%eax
  40da64:	0f b6 95 48 f2 ff ff 	movzbl -0xdb8(%rbp),%edx
  40da6b:	0f b6 8d 44 f2 ff ff 	movzbl -0xdbc(%rbp),%ecx
  40da72:	c1 e0 08             	shl    $0x8,%eax
  40da75:	8d 94 10 b9 79 37 9e 	lea    -0x61c88647(%rax,%rdx,1),%edx
  40da7c:	0f b6 85 47 f2 ff ff 	movzbl -0xdb9(%rbp),%eax
  40da83:	c1 e0 18             	shl    $0x18,%eax
  40da86:	8d 84 08 c4 ba 49 9f 	lea    -0x60b6453c(%rax,%rcx,1),%eax
  40da8d:	0f b6 8d 46 f2 ff ff 	movzbl -0xdba(%rbp),%ecx
  40da94:	c1 e1 10             	shl    $0x10,%ecx
  40da97:	01 c8                	add    %ecx,%eax
  40da99:	0f b6 8d 45 f2 ff ff 	movzbl -0xdbb(%rbp),%ecx
  40daa0:	c1 e1 08             	shl    $0x8,%ecx
  40daa3:	01 c8                	add    %ecx,%eax
  40daa5:	b9 f5 be ed fe       	mov    $0xfeedbef5,%ecx
  40daaa:	29 d0                	sub    %edx,%eax
  40daac:	81 c2 0b 41 12 01    	add    $0x112410b,%edx
  40dab2:	35 6d f7 07 00       	xor    $0x7f76d,%eax
  40dab7:	89 c7                	mov    %eax,%edi
  40dab9:	29 c2                	sub    %eax,%edx
  40dabb:	29 c1                	sub    %eax,%ecx
  40dabd:	c1 e7 08             	shl    $0x8,%edi
  40dac0:	31 d7                	xor    %edx,%edi
  40dac2:	89 fa                	mov    %edi,%edx
  40dac4:	29 f9                	sub    %edi,%ecx
  40dac6:	29 f8                	sub    %edi,%eax
  40dac8:	c1 ea 0d             	shr    $0xd,%edx
  40dacb:	31 ca                	xor    %ecx,%edx
  40dacd:	89 c1                	mov    %eax,%ecx
  40dacf:	89 d0                	mov    %edx,%eax
  40dad1:	29 d1                	sub    %edx,%ecx
  40dad3:	c1 e8 0c             	shr    $0xc,%eax
  40dad6:	31 c1                	xor    %eax,%ecx
  40dad8:	89 f8                	mov    %edi,%eax
  40dada:	29 d0                	sub    %edx,%eax
  40dadc:	89 cf                	mov    %ecx,%edi
  40dade:	29 ca                	sub    %ecx,%edx
  40dae0:	29 c8                	sub    %ecx,%eax
  40dae2:	c1 e7 10             	shl    $0x10,%edi
  40dae5:	31 f8                	xor    %edi,%eax
  40dae7:	89 c7                	mov    %eax,%edi
  40dae9:	29 c2                	sub    %eax,%edx
  40daeb:	29 c1                	sub    %eax,%ecx
  40daed:	c1 ef 05             	shr    $0x5,%edi
  40daf0:	31 fa                	xor    %edi,%edx
  40daf2:	89 d7                	mov    %edx,%edi
  40daf4:	29 d1                	sub    %edx,%ecx
  40daf6:	c1 ef 03             	shr    $0x3,%edi
  40daf9:	31 cf                	xor    %ecx,%edi
  40dafb:	29 d0                	sub    %edx,%eax
  40dafd:	89 f9                	mov    %edi,%ecx
  40daff:	29 f8                	sub    %edi,%eax
  40db01:	29 fa                	sub    %edi,%edx
  40db03:	c1 e1 0a             	shl    $0xa,%ecx
  40db06:	31 c8                	xor    %ecx,%eax
  40db08:	48 8b 8e e8 00 00 00 	mov    0xe8(%rsi),%rcx
  40db0f:	29 c2                	sub    %eax,%edx
  40db11:	c1 e8 0f             	shr    $0xf,%eax
  40db14:	8b 71 08             	mov    0x8(%rcx),%esi
  40db17:	31 d0                	xor    %edx,%eax
  40db19:	8d 56 ff             	lea    -0x1(%rsi),%edx
  40db1c:	21 c2                	and    %eax,%edx
  40db1e:	48 c1 e2 04          	shl    $0x4,%rdx
  40db22:	48 03 11             	add    (%rcx),%rdx
  40db25:	48 8b 1a             	mov    (%rdx),%rbx
  40db28:	48 85 db             	test   %rbx,%rbx
  40db2b:	0f 84 6e f2 ff ff    	je     40cd9f <process_udp.isra.0+0x1df>
  40db31:	48 8b 49 20          	mov    0x20(%rcx),%rcx
  40db35:	48 89 ca             	mov    %rcx,%rdx
  40db38:	48 29 cb             	sub    %rcx,%rbx
  40db3b:	48 f7 da             	neg    %rdx
  40db3e:	eb 13                	jmp    40db53 <process_udp.isra.0+0xf93>
  40db40:	48 8b 9b 08 01 00 00 	mov    0x108(%rbx),%rbx
  40db47:	48 85 db             	test   %rbx,%rbx
  40db4a:	0f 84 4f f2 ff ff    	je     40cd9f <process_udp.isra.0+0x1df>
  40db50:	48 01 d3             	add    %rdx,%rbx
  40db53:	3b 83 1c 01 00 00    	cmp    0x11c(%rbx),%eax
  40db59:	75 e5                	jne    40db40 <process_udp.isra.0+0xf80>
  40db5b:	83 bb 18 01 00 00 06 	cmpl   $0x6,0x118(%rbx)
  40db62:	75 dc                	jne    40db40 <process_udp.isra.0+0xf80>
  40db64:	48 8b 8b 10 01 00 00 	mov    0x110(%rbx),%rcx
  40db6b:	41 8b 34 24          	mov    (%r12),%esi
  40db6f:	39 31                	cmp    %esi,(%rcx)
  40db71:	75 cd                	jne    40db40 <process_udp.isra.0+0xf80>
  40db73:	41 0f b7 74 24 04    	movzwl 0x4(%r12),%esi
  40db79:	66 39 71 04          	cmp    %si,0x4(%rcx)
  40db7d:	75 c1                	jne    40db40 <process_udp.isra.0+0xf80>
  40db7f:	48 8b 8d c8 f0 ff ff 	mov    -0xf38(%rbp),%rcx
  40db86:	48 8b b5 60 f0 ff ff 	mov    -0xfa0(%rbp),%rsi
  40db8d:	31 d2                	xor    %edx,%edx
  40db8f:	48 8d 7b 50          	lea    0x50(%rbx),%rdi
  40db93:	e8 d8 99 ff ff       	call   407570 <auth_edge>
  40db98:	85 c0                	test   %eax,%eax
  40db9a:	0f 85 ff f1 ff ff    	jne    40cd9f <process_udp.isra.0+0x1df>
  40dba0:	48 8b b5 98 f0 ff ff 	mov    -0xf68(%rbp),%rsi
  40dba7:	8b 43 34             	mov    0x34(%rbx),%eax
  40dbaa:	39 46 74             	cmp    %eax,0x74(%rsi)
  40dbad:	0f 84 f4 29 00 00    	je     4105a7 <process_udp.isra.0+0x39e7>
  40dbb3:	85 c0                	test   %eax,%eax
  40dbb5:	0f 88 ec 29 00 00    	js     4105a7 <process_udp.isra.0+0x39e7>
  40dbbb:	48 8b b6 80 00 00 00 	mov    0x80(%rsi),%rsi
  40dbc2:	48 85 f6             	test   %rsi,%rsi
  40dbc5:	0f 84 85 04 00 00    	je     40e050 <process_udp.isra.0+0x1490>
  40dbcb:	0f b6 43 37          	movzbl 0x37(%rbx),%eax
  40dbcf:	0f b6 53 34          	movzbl 0x34(%rbx),%edx
  40dbd3:	b9 c6 ba 49 9f       	mov    $0x9f49bac6,%ecx
  40dbd8:	c1 e0 18             	shl    $0x18,%eax
  40dbdb:	8d 84 10 0d 41 12 01 	lea    0x112410d(%rax,%rdx,1),%eax
  40dbe2:	0f b6 53 36          	movzbl 0x36(%rbx),%edx
  40dbe6:	c1 e2 10             	shl    $0x10,%edx
  40dbe9:	01 d0                	add    %edx,%eax
  40dbeb:	0f b6 53 35          	movzbl 0x35(%rbx),%edx
  40dbef:	c1 e2 08             	shl    $0x8,%edx
  40dbf2:	01 d0                	add    %edx,%eax
  40dbf4:	35 6d f7 07 00       	xor    $0x7f76d,%eax
  40dbf9:	89 c2                	mov    %eax,%edx
  40dbfb:	29 c1                	sub    %eax,%ecx
  40dbfd:	c1 e2 08             	shl    $0x8,%edx
  40dc00:	31 ca                	xor    %ecx,%edx
  40dc02:	b9 f3 be ed fe       	mov    $0xfeedbef3,%ecx
  40dc07:	29 c1                	sub    %eax,%ecx
  40dc09:	89 d7                	mov    %edx,%edi
  40dc0b:	29 d0                	sub    %edx,%eax
  40dc0d:	29 d1                	sub    %edx,%ecx
  40dc0f:	c1 ef 0d             	shr    $0xd,%edi
  40dc12:	31 cf                	xor    %ecx,%edi
  40dc14:	89 f9                	mov    %edi,%ecx
  40dc16:	29 f8                	sub    %edi,%eax
  40dc18:	c1 e9 0c             	shr    $0xc,%ecx
  40dc1b:	31 c1                	xor    %eax,%ecx
  40dc1d:	89 d0                	mov    %edx,%eax
  40dc1f:	29 f8                	sub    %edi,%eax
  40dc21:	89 ca                	mov    %ecx,%edx
  40dc23:	29 cf                	sub    %ecx,%edi
  40dc25:	29 c8                	sub    %ecx,%eax
  40dc27:	c1 e2 10             	shl    $0x10,%edx
  40dc2a:	31 c2                	xor    %eax,%edx
  40dc2c:	89 d0                	mov    %edx,%eax
  40dc2e:	29 d7                	sub    %edx,%edi
  40dc30:	29 d1                	sub    %edx,%ecx
  40dc32:	c1 e8 05             	shr    $0x5,%eax
  40dc35:	31 f8                	xor    %edi,%eax
  40dc37:	89 c7                	mov    %eax,%edi
  40dc39:	29 c1                	sub    %eax,%ecx
  40dc3b:	29 c2                	sub    %eax,%edx
  40dc3d:	c1 ef 03             	shr    $0x3,%edi
  40dc40:	31 cf                	xor    %ecx,%edi
  40dc42:	89 f9                	mov    %edi,%ecx
  40dc44:	29 fa                	sub    %edi,%edx
  40dc46:	c1 e1 0a             	shl    $0xa,%ecx
  40dc49:	31 ca                	xor    %ecx,%edx
  40dc4b:	48 8b 8e 90 08 00 00 	mov    0x890(%rsi),%rcx
  40dc52:	29 f8                	sub    %edi,%eax
  40dc54:	29 d0                	sub    %edx,%eax
  40dc56:	c1 ea 0f             	shr    $0xf,%edx
  40dc59:	8b 71 08             	mov    0x8(%rcx),%esi
  40dc5c:	31 d0                	xor    %edx,%eax
  40dc5e:	8d 56 ff             	lea    -0x1(%rsi),%edx
  40dc61:	21 c2                	and    %eax,%edx
  40dc63:	48 c1 e2 04          	shl    $0x4,%rdx
  40dc67:	48 03 11             	add    (%rcx),%rdx
  40dc6a:	48 8b 32             	mov    (%rdx),%rsi
  40dc6d:	48 85 f6             	test   %rsi,%rsi
  40dc70:	0f 84 da 03 00 00    	je     40e050 <process_udp.isra.0+0x1490>
  40dc76:	48 8b 51 20          	mov    0x20(%rcx),%rdx
  40dc7a:	48 89 d1             	mov    %rdx,%rcx
  40dc7d:	48 29 d6             	sub    %rdx,%rsi
  40dc80:	48 f7 d9             	neg    %rcx
  40dc83:	eb 16                	jmp    40dc9b <process_udp.isra.0+0x10db>
  40dc85:	0f 1f 00             	nopl   (%rax)
  40dc88:	48 8b b6 b0 08 00 00 	mov    0x8b0(%rsi),%rsi
  40dc8f:	48 85 f6             	test   %rsi,%rsi
  40dc92:	0f 84 b8 03 00 00    	je     40e050 <process_udp.isra.0+0x1490>
  40dc98:	48 01 ce             	add    %rcx,%rsi
  40dc9b:	3b 86 c4 08 00 00    	cmp    0x8c4(%rsi),%eax
  40dca1:	75 e5                	jne    40dc88 <process_udp.isra.0+0x10c8>
  40dca3:	83 be c0 08 00 00 04 	cmpl   $0x4,0x8c0(%rsi)
  40dcaa:	75 dc                	jne    40dc88 <process_udp.isra.0+0x10c8>
  40dcac:	48 8b 96 b8 08 00 00 	mov    0x8b8(%rsi),%rdx
  40dcb3:	8b 7b 34             	mov    0x34(%rbx),%edi
  40dcb6:	39 3a                	cmp    %edi,(%rdx)
  40dcb8:	75 ce                	jne    40dc88 <process_udp.isra.0+0x10c8>
  40dcba:	e9 91 03 00 00       	jmp    40e050 <process_udp.isra.0+0x1490>
  40dcbf:	90                   	nop
  40dcc0:	66 0f ef c0          	pxor   %xmm0,%xmm0
  40dcc4:	48 8d 85 10 f2 ff ff 	lea    -0xdf0(%rbp),%rax
  40dccb:	48 83 bd c8 f0 ff ff 	cmpq   $0x0,-0xf38(%rbp)
  40dcd2:	00 
  40dcd3:	48 c7 85 f8 f0 ff ff 	movq   $0x0,-0xf08(%rbp)
  40dcda:	00 00 00 00 
  40dcde:	48 89 85 60 f0 ff ff 	mov    %rax,-0xfa0(%rbp)
  40dce5:	0f 29 85 10 f2 ff ff 	movaps %xmm0,-0xdf0(%rbp)
  40dcec:	0f 29 85 20 f2 ff ff 	movaps %xmm0,-0xde0(%rbp)
  40dcf3:	0f 29 85 30 f2 ff ff 	movaps %xmm0,-0xdd0(%rbp)
  40dcfa:	0f 29 85 40 f2 ff ff 	movaps %xmm0,-0xdc0(%rbp)
  40dd01:	0f 84 bf 32 00 00    	je     410fc6 <process_udp.isra.0+0x4406>
  40dd07:	4c 8b 85 90 f0 ff ff 	mov    -0xf70(%rbp),%r8
  40dd0e:	48 8b 95 b8 f0 ff ff 	mov    -0xf48(%rbp),%rdx
  40dd15:	4c 89 e1             	mov    %r12,%rcx
  40dd18:	4c 8d bd 14 f2 ff ff 	lea    -0xdec(%rbp),%r15
  40dd1f:	48 8b b5 88 f0 ff ff 	mov    -0xf78(%rbp),%rsi
  40dd26:	48 8b bd 60 f0 ff ff 	mov    -0xfa0(%rbp),%rdi
  40dd2d:	e8 5e cd 00 00       	call   41aa90 <decode_REGISTER_SUPER_NAK>
  40dd32:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40dd39:	80 78 16 02          	cmpb   $0x2,0x16(%rax)
  40dd3d:	0f 84 f5 1b 00 00    	je     40f938 <process_udp.isra.0+0x2d78>
  40dd43:	48 8b b5 b0 f0 ff ff 	mov    -0xf50(%rbp),%rsi
  40dd4a:	48 8d bd 30 f3 ff ff 	lea    -0xcd0(%rbp),%rdi
  40dd51:	e8 1a 78 ff ff       	call   405570 <sock_to_cstr>
  40dd56:	48 8d bd f0 f2 ff ff 	lea    -0xd10(%rbp),%rdi
  40dd5d:	4c 89 fe             	mov    %r15,%rsi
  40dd60:	48 89 c3             	mov    %rax,%rbx
  40dd63:	e8 98 6b ff ff       	call   404900 <macaddr_str>
  40dd68:	48 8d 35 86 6b 01 00 	lea    0x16b86(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40dd6f:	49 89 d9             	mov    %rbx,%r9
  40dd72:	48 8d 0d ff 56 01 00 	lea    0x156ff(%rip),%rcx        # 423478 <_IO_stdin_used+0x2478>
  40dd79:	49 89 c0             	mov    %rax,%r8
  40dd7c:	ba 1b 09 00 00       	mov    $0x91b,%edx
  40dd81:	31 c0                	xor    %eax,%eax
  40dd83:	bf 03 00 00 00       	mov    $0x3,%edi
  40dd88:	e8 e3 65 ff ff       	call   404370 <_traceEvent>
  40dd8d:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40dd94:	48 8b 70 48          	mov    0x48(%rax),%rsi
  40dd98:	48 85 f6             	test   %rsi,%rsi
  40dd9b:	0f 84 fe ef ff ff    	je     40cd9f <process_udp.isra.0+0x1df>
  40dda1:	0f b6 85 19 f2 ff ff 	movzbl -0xde7(%rbp),%eax
  40dda8:	0f b6 95 18 f2 ff ff 	movzbl -0xde8(%rbp),%edx
  40ddaf:	bf f5 be ed fe       	mov    $0xfeedbef5,%edi
  40ddb4:	0f b6 8d 14 f2 ff ff 	movzbl -0xdec(%rbp),%ecx
  40ddbb:	c1 e0 08             	shl    $0x8,%eax
  40ddbe:	8d 94 10 b9 79 37 9e 	lea    -0x61c88647(%rax,%rdx,1),%edx
  40ddc5:	0f b6 85 17 f2 ff ff 	movzbl -0xde9(%rbp),%eax
  40ddcc:	c1 e0 18             	shl    $0x18,%eax
  40ddcf:	8d 84 08 c4 ba 49 9f 	lea    -0x60b6453c(%rax,%rcx,1),%eax
  40ddd6:	0f b6 8d 16 f2 ff ff 	movzbl -0xdea(%rbp),%ecx
  40dddd:	c1 e1 10             	shl    $0x10,%ecx
  40dde0:	01 c8                	add    %ecx,%eax
  40dde2:	0f b6 8d 15 f2 ff ff 	movzbl -0xdeb(%rbp),%ecx
  40dde9:	c1 e1 08             	shl    $0x8,%ecx
  40ddec:	01 c8                	add    %ecx,%eax
  40ddee:	29 d0                	sub    %edx,%eax
  40ddf0:	81 c2 0b 41 12 01    	add    $0x112410b,%edx
  40ddf6:	35 6d f7 07 00       	xor    $0x7f76d,%eax
  40ddfb:	29 c2                	sub    %eax,%edx
  40ddfd:	89 c1                	mov    %eax,%ecx
  40ddff:	c1 e0 08             	shl    $0x8,%eax
  40de02:	31 d0                	xor    %edx,%eax
  40de04:	29 cf                	sub    %ecx,%edi
  40de06:	89 c2                	mov    %eax,%edx
  40de08:	29 c7                	sub    %eax,%edi
  40de0a:	29 c1                	sub    %eax,%ecx
  40de0c:	c1 ea 0d             	shr    $0xd,%edx
  40de0f:	31 fa                	xor    %edi,%edx
  40de11:	89 d7                	mov    %edx,%edi
  40de13:	29 d1                	sub    %edx,%ecx
  40de15:	29 d0                	sub    %edx,%eax
  40de17:	c1 ef 0c             	shr    $0xc,%edi
  40de1a:	31 f9                	xor    %edi,%ecx
  40de1c:	89 cf                	mov    %ecx,%edi
  40de1e:	29 c8                	sub    %ecx,%eax
  40de20:	29 ca                	sub    %ecx,%edx
  40de22:	c1 e7 10             	shl    $0x10,%edi
  40de25:	31 f8                	xor    %edi,%eax
  40de27:	89 c7                	mov    %eax,%edi
  40de29:	29 c2                	sub    %eax,%edx
  40de2b:	29 c1                	sub    %eax,%ecx
  40de2d:	c1 ef 05             	shr    $0x5,%edi
  40de30:	31 fa                	xor    %edi,%edx
  40de32:	89 d7                	mov    %edx,%edi
  40de34:	29 d1                	sub    %edx,%ecx
  40de36:	c1 ef 03             	shr    $0x3,%edi
  40de39:	31 cf                	xor    %ecx,%edi
  40de3b:	29 d0                	sub    %edx,%eax
  40de3d:	89 f9                	mov    %edi,%ecx
  40de3f:	29 f8                	sub    %edi,%eax
  40de41:	29 fa                	sub    %edi,%edx
  40de43:	c1 e1 0a             	shl    $0xa,%ecx
  40de46:	31 c8                	xor    %ecx,%eax
  40de48:	48 8b 8e e8 00 00 00 	mov    0xe8(%rsi),%rcx
  40de4f:	29 c2                	sub    %eax,%edx
  40de51:	c1 e8 0f             	shr    $0xf,%eax
  40de54:	8b 71 08             	mov    0x8(%rcx),%esi
  40de57:	31 d0                	xor    %edx,%eax
  40de59:	8d 56 ff             	lea    -0x1(%rsi),%edx
  40de5c:	21 c2                	and    %eax,%edx
  40de5e:	48 c1 e2 04          	shl    $0x4,%rdx
  40de62:	48 03 11             	add    (%rcx),%rdx
  40de65:	4c 8b 22             	mov    (%rdx),%r12
  40de68:	4d 85 e4             	test   %r12,%r12
  40de6b:	0f 84 2e ef ff ff    	je     40cd9f <process_udp.isra.0+0x1df>
  40de71:	48 8b 49 20          	mov    0x20(%rcx),%rcx
  40de75:	48 89 ca             	mov    %rcx,%rdx
  40de78:	49 29 cc             	sub    %rcx,%r12
  40de7b:	48 f7 da             	neg    %rdx
  40de7e:	eb 14                	jmp    40de94 <process_udp.isra.0+0x12d4>
  40de80:	4d 8b a4 24 08 01 00 	mov    0x108(%r12),%r12
  40de87:	00 
  40de88:	4d 85 e4             	test   %r12,%r12
  40de8b:	0f 84 0e ef ff ff    	je     40cd9f <process_udp.isra.0+0x1df>
  40de91:	49 01 d4             	add    %rdx,%r12
  40de94:	41 3b 84 24 1c 01 00 	cmp    0x11c(%r12),%eax
  40de9b:	00 
  40de9c:	75 e2                	jne    40de80 <process_udp.isra.0+0x12c0>
  40de9e:	41 83 bc 24 18 01 00 	cmpl   $0x6,0x118(%r12)
  40dea5:	00 06 
  40dea7:	75 d7                	jne    40de80 <process_udp.isra.0+0x12c0>
  40dea9:	49 8b 8c 24 10 01 00 	mov    0x110(%r12),%rcx
  40deb0:	00 
  40deb1:	41 8b 37             	mov    (%r15),%esi
  40deb4:	39 31                	cmp    %esi,(%rcx)
  40deb6:	75 c8                	jne    40de80 <process_udp.isra.0+0x12c0>
  40deb8:	41 0f b7 77 04       	movzwl 0x4(%r15),%esi
  40debd:	66 39 71 04          	cmp    %si,0x4(%rcx)
  40dec1:	75 bd                	jne    40de80 <process_udp.isra.0+0x12c0>
  40dec3:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40deca:	80 78 14 00          	cmpb   $0x0,0x14(%rax)
  40dece:	0f 85 cb ee ff ff    	jne    40cd9f <process_udp.isra.0+0x1df>
  40ded4:	48 8d 85 c0 f7 ff ff 	lea    -0x840(%rbp),%rax
  40dedb:	48 8b 8d 60 f0 ff ff 	mov    -0xfa0(%rbp),%rcx
  40dee2:	48 8b 95 88 f0 ff ff 	mov    -0xf78(%rbp),%rdx
  40dee9:	48 8d 9d f8 f0 ff ff 	lea    -0xf08(%rbp),%rbx
  40def0:	48 89 de             	mov    %rbx,%rsi
  40def3:	48 89 c7             	mov    %rax,%rdi
  40def6:	48 89 85 c0 f0 ff ff 	mov    %rax,-0xf40(%rbp)
  40defd:	e8 ae ca 00 00       	call   41a9b0 <encode_REGISTER_SUPER_NAK>
  40df02:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40df09:	80 78 16 02          	cmpb   $0x2,0x16(%rax)
  40df0d:	0f 84 06 2a 00 00    	je     410919 <process_udp.isra.0+0x3d59>
  40df13:	48 8b 9d 98 f0 ff ff 	mov    -0xf68(%rbp),%rbx
  40df1a:	48 8b 8d f8 f0 ff ff 	mov    -0xf08(%rbp),%rcx
  40df21:	4c 89 e6             	mov    %r12,%rsi
  40df24:	48 8b 95 c0 f0 ff ff 	mov    -0xf40(%rbp),%rdx
  40df2b:	48 89 df             	mov    %rbx,%rdi
  40df2e:	e8 4d b1 ff ff       	call   409080 <sendto_peer>
  40df33:	41 8b 44 24 34       	mov    0x34(%r12),%eax
  40df38:	39 43 74             	cmp    %eax,0x74(%rbx)
  40df3b:	0f 84 05 21 00 00    	je     410046 <process_udp.isra.0+0x3486>
  40df41:	85 c0                	test   %eax,%eax
  40df43:	0f 88 fd 20 00 00    	js     410046 <process_udp.isra.0+0x3486>
  40df49:	48 8b b3 80 00 00 00 	mov    0x80(%rbx),%rsi
  40df50:	48 85 f6             	test   %rsi,%rsi
  40df53:	0f 84 f7 00 00 00    	je     40e050 <process_udp.isra.0+0x1490>
  40df59:	41 0f b6 44 24 37    	movzbl 0x37(%r12),%eax
  40df5f:	41 0f b6 54 24 34    	movzbl 0x34(%r12),%edx
  40df65:	b9 f3 be ed fe       	mov    $0xfeedbef3,%ecx
  40df6a:	c1 e0 18             	shl    $0x18,%eax
  40df6d:	8d 84 10 0d 41 12 01 	lea    0x112410d(%rax,%rdx,1),%eax
  40df74:	41 0f b6 54 24 36    	movzbl 0x36(%r12),%edx
  40df7a:	c1 e2 10             	shl    $0x10,%edx
  40df7d:	01 d0                	add    %edx,%eax
  40df7f:	41 0f b6 54 24 35    	movzbl 0x35(%r12),%edx
  40df85:	c1 e2 08             	shl    $0x8,%edx
  40df88:	01 d0                	add    %edx,%eax
  40df8a:	ba c6 ba 49 9f       	mov    $0x9f49bac6,%edx
  40df8f:	35 6d f7 07 00       	xor    $0x7f76d,%eax
  40df94:	89 c7                	mov    %eax,%edi
  40df96:	29 c2                	sub    %eax,%edx
  40df98:	29 c1                	sub    %eax,%ecx
  40df9a:	c1 e7 08             	shl    $0x8,%edi
  40df9d:	31 d7                	xor    %edx,%edi
  40df9f:	89 fa                	mov    %edi,%edx
  40dfa1:	29 f9                	sub    %edi,%ecx
  40dfa3:	29 f8                	sub    %edi,%eax
  40dfa5:	c1 ea 0d             	shr    $0xd,%edx
  40dfa8:	31 ca                	xor    %ecx,%edx
  40dfaa:	89 d1                	mov    %edx,%ecx
  40dfac:	29 d0                	sub    %edx,%eax
  40dfae:	29 d7                	sub    %edx,%edi
  40dfb0:	c1 e9 0c             	shr    $0xc,%ecx
  40dfb3:	31 c1                	xor    %eax,%ecx
  40dfb5:	89 c8                	mov    %ecx,%eax
  40dfb7:	29 cf                	sub    %ecx,%edi
  40dfb9:	29 ca                	sub    %ecx,%edx
  40dfbb:	c1 e0 10             	shl    $0x10,%eax
  40dfbe:	31 f8                	xor    %edi,%eax
  40dfc0:	29 c2                	sub    %eax,%edx
  40dfc2:	29 c1                	sub    %eax,%ecx
  40dfc4:	89 d7                	mov    %edx,%edi
  40dfc6:	89 c2                	mov    %eax,%edx
  40dfc8:	c1 ea 05             	shr    $0x5,%edx
  40dfcb:	31 fa                	xor    %edi,%edx
  40dfcd:	89 d7                	mov    %edx,%edi
  40dfcf:	29 d1                	sub    %edx,%ecx
  40dfd1:	29 d0                	sub    %edx,%eax
  40dfd3:	c1 ef 03             	shr    $0x3,%edi
  40dfd6:	31 cf                	xor    %ecx,%edi
  40dfd8:	29 f8                	sub    %edi,%eax
  40dfda:	89 c1                	mov    %eax,%ecx
  40dfdc:	89 f8                	mov    %edi,%eax
  40dfde:	c1 e0 0a             	shl    $0xa,%eax
  40dfe1:	31 c8                	xor    %ecx,%eax
  40dfe3:	48 8b 8e 90 08 00 00 	mov    0x890(%rsi),%rcx
  40dfea:	29 fa                	sub    %edi,%edx
  40dfec:	29 c2                	sub    %eax,%edx
  40dfee:	c1 e8 0f             	shr    $0xf,%eax
  40dff1:	8b 71 08             	mov    0x8(%rcx),%esi
  40dff4:	31 d0                	xor    %edx,%eax
  40dff6:	8d 56 ff             	lea    -0x1(%rsi),%edx
  40dff9:	21 c2                	and    %eax,%edx
  40dffb:	48 c1 e2 04          	shl    $0x4,%rdx
  40dfff:	48 03 11             	add    (%rcx),%rdx
  40e002:	48 8b 32             	mov    (%rdx),%rsi
  40e005:	48 85 f6             	test   %rsi,%rsi
  40e008:	74 46                	je     40e050 <process_udp.isra.0+0x1490>
  40e00a:	48 8b 51 20          	mov    0x20(%rcx),%rdx
  40e00e:	48 89 d1             	mov    %rdx,%rcx
  40e011:	48 29 d6             	sub    %rdx,%rsi
  40e014:	48 f7 d9             	neg    %rcx
  40e017:	eb 16                	jmp    40e02f <process_udp.isra.0+0x146f>
  40e019:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  40e020:	48 8b b6 b0 08 00 00 	mov    0x8b0(%rsi),%rsi
  40e027:	48 85 f6             	test   %rsi,%rsi
  40e02a:	74 24                	je     40e050 <process_udp.isra.0+0x1490>
  40e02c:	48 01 ce             	add    %rcx,%rsi
  40e02f:	3b 86 c4 08 00 00    	cmp    0x8c4(%rsi),%eax
  40e035:	75 e9                	jne    40e020 <process_udp.isra.0+0x1460>
  40e037:	83 be c0 08 00 00 04 	cmpl   $0x4,0x8c0(%rsi)
  40e03e:	75 e0                	jne    40e020 <process_udp.isra.0+0x1460>
  40e040:	48 8b 96 b8 08 00 00 	mov    0x8b8(%rsi),%rdx
  40e047:	8b 12                	mov    (%rdx),%edx
  40e049:	41 39 54 24 34       	cmp    %edx,0x34(%r12)
  40e04e:	75 d0                	jne    40e020 <process_udp.isra.0+0x1460>
  40e050:	48 8b bd 98 f0 ff ff 	mov    -0xf68(%rbp),%rdi
  40e057:	e8 74 ab ff ff       	call   408bd0 <close_tcp_connection>
  40e05c:	e9 3e ed ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40e061:	31 c0                	xor    %eax,%eax
  40e063:	b9 0c 00 00 00       	mov    $0xc,%ecx
  40e068:	48 8b 75 10          	mov    0x10(%rbp),%rsi
  40e06c:	66 0f ef c0          	pxor   %xmm0,%xmm0
  40e070:	48 8d bd a0 f1 ff ff 	lea    -0xe60(%rbp),%rdi
  40e077:	4c 8b 85 90 f0 ff ff 	mov    -0xf70(%rbp),%r8
  40e07e:	48 8b 95 b8 f0 ff ff 	mov    -0xf48(%rbp),%rdx
  40e085:	48 c7 85 f0 f0 ff ff 	movq   $0x0,-0xf10(%rbp)
  40e08c:	00 00 00 00 
  40e090:	48 89 bd 50 f0 ff ff 	mov    %rdi,-0xfb0(%rbp)
  40e097:	f3 48 ab             	rep stos %rax,%es:(%rdi)
  40e09a:	48 8b 85 98 f0 ff ff 	mov    -0xf68(%rbp),%rax
  40e0a1:	4c 89 e1             	mov    %r12,%rcx
  40e0a4:	c7 85 d4 f0 ff ff 00 	movl   $0x0,-0xf2c(%rbp)
  40e0ab:	00 00 00 
  40e0ae:	0f 29 85 60 f1 ff ff 	movaps %xmm0,-0xea0(%rbp)
  40e0b5:	48 83 40 30 01       	addq   $0x1,0x30(%rax)
  40e0ba:	48 89 70 58          	mov    %rsi,0x58(%rax)
  40e0be:	48 8d 85 10 f2 ff ff 	lea    -0xdf0(%rbp),%rax
  40e0c5:	48 8b b5 88 f0 ff ff 	mov    -0xf78(%rbp),%rsi
  40e0cc:	48 89 85 60 f0 ff ff 	mov    %rax,-0xfa0(%rbp)
  40e0d3:	0f 29 85 70 f1 ff ff 	movaps %xmm0,-0xe90(%rbp)
  40e0da:	c7 07 00 00 00 00    	movl   $0x0,(%rdi)
  40e0e0:	48 89 c7             	mov    %rax,%rdi
  40e0e3:	0f 29 85 80 f1 ff ff 	movaps %xmm0,-0xe80(%rbp)
  40e0ea:	0f 29 85 90 f1 ff ff 	movaps %xmm0,-0xe70(%rbp)
  40e0f1:	e8 2a bd 00 00       	call   419e20 <decode_REGISTER_SUPER>
  40e0f6:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40e0fd:	48 85 c0             	test   %rax,%rax
  40e100:	0f 84 aa 1b 00 00    	je     40fcb0 <process_udp.isra.0+0x30f0>
  40e106:	80 78 16 02          	cmpb   $0x2,0x16(%rax)
  40e10a:	0f 84 ea 0e 00 00    	je     40effa <process_udp.isra.0+0x243a>
  40e110:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40e117:	4c 8b 40 58          	mov    0x58(%rax),%r8
  40e11b:	4d 85 c0             	test   %r8,%r8
  40e11e:	0f 84 e6 09 00 00    	je     40eb0a <process_udp.isra.0+0x1f4a>
  40e124:	b8 ef be ed fe       	mov    $0xfeedbeef,%eax
  40e129:	b9 b9 79 37 9e       	mov    $0x9e3779b9,%ecx
  40e12e:	ba b9 79 37 9e       	mov    $0x9e3779b9,%edx
  40e133:	48 8b bd 60 f0 ff ff 	mov    -0xfa0(%rbp),%rdi
  40e13a:	4c 8d 8d 28 f2 ff ff 	lea    -0xdd8(%rbp),%r9
  40e141:	0f b6 77 41          	movzbl 0x41(%rdi),%esi
  40e145:	44 0f b6 57 42       	movzbl 0x42(%rdi),%r10d
  40e14a:	c1 e6 08             	shl    $0x8,%esi
  40e14d:	41 c1 e2 10          	shl    $0x10,%r10d
  40e151:	44 01 d6             	add    %r10d,%esi
  40e154:	44 0f b6 57 40       	movzbl 0x40(%rdi),%r10d
  40e159:	44 01 d6             	add    %r10d,%esi
  40e15c:	44 0f b6 57 43       	movzbl 0x43(%rdi),%r10d
  40e161:	41 c1 e2 18          	shl    $0x18,%r10d
  40e165:	44 01 d6             	add    %r10d,%esi
  40e168:	44 0f b6 57 46       	movzbl 0x46(%rdi),%r10d
  40e16d:	01 f1                	add    %esi,%ecx
  40e16f:	0f b6 77 45          	movzbl 0x45(%rdi),%esi
  40e173:	41 c1 e2 10          	shl    $0x10,%r10d
  40e177:	c1 e6 08             	shl    $0x8,%esi
  40e17a:	44 01 d6             	add    %r10d,%esi
  40e17d:	44 0f b6 57 44       	movzbl 0x44(%rdi),%r10d
  40e182:	44 01 d6             	add    %r10d,%esi
  40e185:	44 0f b6 57 47       	movzbl 0x47(%rdi),%r10d
  40e18a:	41 c1 e2 18          	shl    $0x18,%r10d
  40e18e:	44 01 d6             	add    %r10d,%esi
  40e191:	44 0f b6 57 3e       	movzbl 0x3e(%rdi),%r10d
  40e196:	01 f0                	add    %esi,%eax
  40e198:	0f b6 77 3d          	movzbl 0x3d(%rdi),%esi
  40e19c:	41 c1 e2 10          	shl    $0x10,%r10d
  40e1a0:	c1 e6 08             	shl    $0x8,%esi
  40e1a3:	44 01 d6             	add    %r10d,%esi
  40e1a6:	44 0f b6 57 3c       	movzbl 0x3c(%rdi),%r10d
  40e1ab:	44 01 d6             	add    %r10d,%esi
  40e1ae:	44 0f b6 57 3f       	movzbl 0x3f(%rdi),%r10d
  40e1b3:	41 c1 e2 18          	shl    $0x18,%r10d
  40e1b7:	44 01 d6             	add    %r10d,%esi
  40e1ba:	29 ce                	sub    %ecx,%esi
  40e1bc:	29 c1                	sub    %eax,%ecx
  40e1be:	29 c6                	sub    %eax,%esi
  40e1c0:	01 f2                	add    %esi,%edx
  40e1c2:	89 c6                	mov    %eax,%esi
  40e1c4:	c1 ee 0d             	shr    $0xd,%esi
  40e1c7:	31 f2                	xor    %esi,%edx
  40e1c9:	89 ce                	mov    %ecx,%esi
  40e1cb:	89 d1                	mov    %edx,%ecx
  40e1cd:	29 d6                	sub    %edx,%esi
  40e1cf:	29 d0                	sub    %edx,%eax
  40e1d1:	c1 e1 08             	shl    $0x8,%ecx
  40e1d4:	31 f1                	xor    %esi,%ecx
  40e1d6:	29 c8                	sub    %ecx,%eax
  40e1d8:	89 c6                	mov    %eax,%esi
  40e1da:	89 c8                	mov    %ecx,%eax
  40e1dc:	c1 e8 0d             	shr    $0xd,%eax
  40e1df:	31 f0                	xor    %esi,%eax
  40e1e1:	29 ca                	sub    %ecx,%edx
  40e1e3:	48 83 c7 0c          	add    $0xc,%rdi
  40e1e7:	89 d6                	mov    %edx,%esi
  40e1e9:	89 c2                	mov    %eax,%edx
  40e1eb:	29 c1                	sub    %eax,%ecx
  40e1ed:	29 c6                	sub    %eax,%esi
  40e1ef:	c1 ea 0c             	shr    $0xc,%edx
  40e1f2:	31 f2                	xor    %esi,%edx
  40e1f4:	89 ce                	mov    %ecx,%esi
  40e1f6:	89 d1                	mov    %edx,%ecx
  40e1f8:	29 d6                	sub    %edx,%esi
  40e1fa:	29 d0                	sub    %edx,%eax
  40e1fc:	c1 e1 10             	shl    $0x10,%ecx
  40e1ff:	31 f1                	xor    %esi,%ecx
  40e201:	29 c8                	sub    %ecx,%eax
  40e203:	29 ca                	sub    %ecx,%edx
  40e205:	89 c6                	mov    %eax,%esi
  40e207:	89 c8                	mov    %ecx,%eax
  40e209:	c1 e8 05             	shr    $0x5,%eax
  40e20c:	31 f0                	xor    %esi,%eax
  40e20e:	89 d6                	mov    %edx,%esi
  40e210:	89 c2                	mov    %eax,%edx
  40e212:	29 c6                	sub    %eax,%esi
  40e214:	29 c1                	sub    %eax,%ecx
  40e216:	c1 ea 03             	shr    $0x3,%edx
  40e219:	31 f2                	xor    %esi,%edx
  40e21b:	89 d6                	mov    %edx,%esi
  40e21d:	29 d1                	sub    %edx,%ecx
  40e21f:	29 d0                	sub    %edx,%eax
  40e221:	c1 e6 0a             	shl    $0xa,%esi
  40e224:	31 f1                	xor    %esi,%ecx
  40e226:	89 ce                	mov    %ecx,%esi
  40e228:	29 c8                	sub    %ecx,%eax
  40e22a:	c1 ee 0f             	shr    $0xf,%esi
  40e22d:	31 f0                	xor    %esi,%eax
  40e22f:	4c 39 cf             	cmp    %r9,%rdi
  40e232:	0f 85 09 ff ff ff    	jne    40e141 <process_udp.isra.0+0x1581>
  40e238:	0f b6 b5 6b f2 ff ff 	movzbl -0xd95(%rbp),%esi
  40e23f:	0f b6 bd 6a f2 ff ff 	movzbl -0xd96(%rbp),%edi
  40e246:	83 c0 20             	add    $0x20,%eax
  40e249:	c1 e7 10             	shl    $0x10,%edi
  40e24c:	c1 e6 18             	shl    $0x18,%esi
  40e24f:	01 fe                	add    %edi,%esi
  40e251:	0f b6 bd 68 f2 ff ff 	movzbl -0xd98(%rbp),%edi
  40e258:	01 fe                	add    %edi,%esi
  40e25a:	0f b6 bd 69 f2 ff ff 	movzbl -0xd97(%rbp),%edi
  40e261:	c1 e7 08             	shl    $0x8,%edi
  40e264:	01 fe                	add    %edi,%esi
  40e266:	0f b6 bd 66 f2 ff ff 	movzbl -0xd9a(%rbp),%edi
  40e26d:	01 f1                	add    %esi,%ecx
  40e26f:	0f b6 b5 67 f2 ff ff 	movzbl -0xd99(%rbp),%esi
  40e276:	c1 e7 10             	shl    $0x10,%edi
  40e279:	c1 e6 18             	shl    $0x18,%esi
  40e27c:	01 fe                	add    %edi,%esi
  40e27e:	0f b6 bd 64 f2 ff ff 	movzbl -0xd9c(%rbp),%edi
  40e285:	01 fe                	add    %edi,%esi
  40e287:	0f b6 bd 65 f2 ff ff 	movzbl -0xd9b(%rbp),%edi
  40e28e:	c1 e7 08             	shl    $0x8,%edi
  40e291:	01 fe                	add    %edi,%esi
  40e293:	01 f2                	add    %esi,%edx
  40e295:	89 c6                	mov    %eax,%esi
  40e297:	29 c2                	sub    %eax,%edx
  40e299:	c1 ee 0d             	shr    $0xd,%esi
  40e29c:	29 ca                	sub    %ecx,%edx
  40e29e:	29 c1                	sub    %eax,%ecx
  40e2a0:	31 d6                	xor    %edx,%esi
  40e2a2:	89 f2                	mov    %esi,%edx
  40e2a4:	29 f1                	sub    %esi,%ecx
  40e2a6:	29 f0                	sub    %esi,%eax
  40e2a8:	c1 e2 08             	shl    $0x8,%edx
  40e2ab:	31 ca                	xor    %ecx,%edx
  40e2ad:	89 d1                	mov    %edx,%ecx
  40e2af:	29 d0                	sub    %edx,%eax
  40e2b1:	29 d6                	sub    %edx,%esi
  40e2b3:	c1 e9 0d             	shr    $0xd,%ecx
  40e2b6:	31 c8                	xor    %ecx,%eax
  40e2b8:	89 f1                	mov    %esi,%ecx
  40e2ba:	89 c6                	mov    %eax,%esi
  40e2bc:	29 c1                	sub    %eax,%ecx
  40e2be:	29 c2                	sub    %eax,%edx
  40e2c0:	c1 ee 0c             	shr    $0xc,%esi
  40e2c3:	31 f1                	xor    %esi,%ecx
  40e2c5:	89 ce                	mov    %ecx,%esi
  40e2c7:	29 ca                	sub    %ecx,%edx
  40e2c9:	29 c8                	sub    %ecx,%eax
  40e2cb:	c1 e6 10             	shl    $0x10,%esi
  40e2ce:	31 f2                	xor    %esi,%edx
  40e2d0:	89 d6                	mov    %edx,%esi
  40e2d2:	29 d0                	sub    %edx,%eax
  40e2d4:	29 d1                	sub    %edx,%ecx
  40e2d6:	c1 ee 05             	shr    $0x5,%esi
  40e2d9:	31 f0                	xor    %esi,%eax
  40e2db:	89 c6                	mov    %eax,%esi
  40e2dd:	29 c1                	sub    %eax,%ecx
  40e2df:	29 c2                	sub    %eax,%edx
  40e2e1:	c1 ee 03             	shr    $0x3,%esi
  40e2e4:	31 f1                	xor    %esi,%ecx
  40e2e6:	89 ce                	mov    %ecx,%esi
  40e2e8:	29 ca                	sub    %ecx,%edx
  40e2ea:	29 c8                	sub    %ecx,%eax
  40e2ec:	49 8b 48 58          	mov    0x58(%r8),%rcx
  40e2f0:	c1 e6 0a             	shl    $0xa,%esi
  40e2f3:	31 f2                	xor    %esi,%edx
  40e2f5:	29 d0                	sub    %edx,%eax
  40e2f7:	c1 ea 0f             	shr    $0xf,%edx
  40e2fa:	31 c2                	xor    %eax,%edx
  40e2fc:	8b 41 08             	mov    0x8(%rcx),%eax
  40e2ff:	83 e8 01             	sub    $0x1,%eax
  40e302:	21 d0                	and    %edx,%eax
  40e304:	48 c1 e0 04          	shl    $0x4,%rax
  40e308:	48 03 01             	add    (%rcx),%rax
  40e30b:	48 8b 38             	mov    (%rax),%rdi
  40e30e:	48 85 ff             	test   %rdi,%rdi
  40e311:	0f 84 d4 07 00 00    	je     40eaeb <process_udp.isra.0+0x1f2b>
  40e317:	48 8b 41 20          	mov    0x20(%rcx),%rax
  40e31b:	48 89 c6             	mov    %rax,%rsi
  40e31e:	48 29 c7             	sub    %rax,%rdi
  40e321:	48 f7 de             	neg    %rsi
  40e324:	49 89 fa             	mov    %rdi,%r10
  40e327:	eb 17                	jmp    40e340 <process_udp.isra.0+0x1780>
  40e329:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  40e330:	4d 8b 52 78          	mov    0x78(%r10),%r10
  40e334:	4d 85 d2             	test   %r10,%r10
  40e337:	0f 84 ae 07 00 00    	je     40eaeb <process_udp.isra.0+0x1f2b>
  40e33d:	49 01 f2             	add    %rsi,%r10
  40e340:	41 3b 92 8c 00 00 00 	cmp    0x8c(%r10),%edx
  40e347:	75 e7                	jne    40e330 <process_udp.isra.0+0x1770>
  40e349:	41 83 ba 88 00 00 00 	cmpl   $0x20,0x88(%r10)
  40e350:	20 
  40e351:	75 dd                	jne    40e330 <process_udp.isra.0+0x1770>
  40e353:	49 8b ba 80 00 00 00 	mov    0x80(%r10),%rdi
  40e35a:	48 8b 07             	mov    (%rdi),%rax
  40e35d:	48 8b 4f 08          	mov    0x8(%rdi),%rcx
  40e361:	48 33 85 4c f2 ff ff 	xor    -0xdb4(%rbp),%rax
  40e368:	48 33 8d 54 f2 ff ff 	xor    -0xdac(%rbp),%rcx
  40e36f:	48 09 c8             	or     %rcx,%rax
  40e372:	75 bc                	jne    40e330 <process_udp.isra.0+0x1770>
  40e374:	48 8b 47 10          	mov    0x10(%rdi),%rax
  40e378:	48 8b 4f 18          	mov    0x18(%rdi),%rcx
  40e37c:	48 33 85 5c f2 ff ff 	xor    -0xda4(%rbp),%rax
  40e383:	48 33 8d 64 f2 ff ff 	xor    -0xd9c(%rbp),%rcx
  40e38a:	48 09 c8             	or     %rcx,%rax
  40e38d:	75 a1                	jne    40e330 <process_udp.isra.0+0x1770>
  40e38f:	49 8b 72 40          	mov    0x40(%r10),%rsi
  40e393:	48 8d bd 80 f2 ff ff 	lea    -0xd80(%rbp),%rdi
  40e39a:	4c 89 95 b0 f0 ff ff 	mov    %r10,-0xf50(%rbp)
  40e3a1:	e8 fa ad 00 00       	call   4191a0 <speck_128_encrypt>
  40e3a6:	48 8b b5 b8 f0 ff ff 	mov    -0xf48(%rbp),%rsi
  40e3ad:	48 8b 8d c0 f0 ff ff 	mov    -0xf40(%rbp),%rcx
  40e3b4:	48 8b 85 80 f2 ff ff 	mov    -0xd80(%rbp),%rax
  40e3bb:	48 8b 95 88 f2 ff ff 	mov    -0xd78(%rbp),%rdx
  40e3c2:	48 33 44 0e f0       	xor    -0x10(%rsi,%rcx,1),%rax
  40e3c7:	48 33 54 0e f8       	xor    -0x8(%rsi,%rcx,1),%rdx
  40e3cc:	48 09 d0             	or     %rdx,%rax
  40e3cf:	4c 8b 95 b0 f0 ff ff 	mov    -0xf50(%rbp),%r10
  40e3d6:	0f 84 31 07 00 00    	je     40eb0d <process_udp.isra.0+0x1f4d>
  40e3dc:	48 8d 0d 1d 4d 01 00 	lea    0x14d1d(%rip),%rcx        # 423100 <_IO_stdin_used+0x2100>
  40e3e3:	ba ae 07 00 00       	mov    $0x7ae,%edx
  40e3e8:	48 8d 35 06 65 01 00 	lea    0x16506(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40e3ef:	31 c0                	xor    %eax,%eax
  40e3f1:	bf 03 00 00 00       	mov    $0x3,%edi
  40e3f6:	e8 75 5f ff ff       	call   404370 <_traceEvent>
  40e3fb:	e9 9f e9 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40e400:	48 8d 0d 51 4c 01 00 	lea    0x14c51(%rip),%rcx        # 423058 <_IO_stdin_used+0x2058>
  40e407:	ba 4c 07 00 00       	mov    $0x74c,%edx
  40e40c:	48 8d 35 e2 64 01 00 	lea    0x164e2(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40e413:	31 c0                	xor    %eax,%eax
  40e415:	bf 04 00 00 00       	mov    $0x4,%edi
  40e41a:	e8 51 5f ff ff       	call   404370 <_traceEvent>
  40e41f:	e9 7b e9 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40e424:	44 0f b6 c3          	movzbl %bl,%r8d
  40e428:	ba 0e 0a 00 00       	mov    $0xa0e,%edx
  40e42d:	bf 01 00 00 00       	mov    $0x1,%edi
  40e432:	31 c0                	xor    %eax,%eax
  40e434:	48 8d 0d cd 51 01 00 	lea    0x151cd(%rip),%rcx        # 423608 <_IO_stdin_used+0x2608>
  40e43b:	48 8d 35 b3 64 01 00 	lea    0x164b3(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40e442:	e8 29 5f ff ff       	call   404370 <_traceEvent>
  40e447:	e9 53 e9 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40e44c:	48 83 bd c8 f0 ff ff 	cmpq   $0x0,-0xf38(%rbp)
  40e453:	00 
  40e454:	48 c7 85 f8 f0 ff ff 	movq   $0x0,-0xf08(%rbp)
  40e45b:	00 00 00 00 
  40e45f:	0f 84 c5 29 00 00    	je     410e2a <process_udp.isra.0+0x426a>
  40e465:	48 8b 85 98 f0 ff ff 	mov    -0xf68(%rbp),%rax
  40e46c:	48 8b 75 10          	mov    0x10(%rbp),%rsi
  40e470:	4c 89 e1             	mov    %r12,%rcx
  40e473:	4c 8b 85 90 f0 ff ff 	mov    -0xf70(%rbp),%r8
  40e47a:	48 8b 95 b8 f0 ff ff 	mov    -0xf48(%rbp),%rdx
  40e481:	48 89 70 50          	mov    %rsi,0x50(%rax)
  40e485:	48 8d 85 10 f2 ff ff 	lea    -0xdf0(%rbp),%rax
  40e48c:	48 8b b5 88 f0 ff ff 	mov    -0xf78(%rbp),%rsi
  40e493:	48 89 c7             	mov    %rax,%rdi
  40e496:	48 89 85 60 f0 ff ff 	mov    %rax,-0xfa0(%rbp)
  40e49d:	e8 ae c8 00 00       	call   41ad50 <decode_PACKET>
  40e4a2:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40e4a9:	80 78 16 02          	cmpb   $0x2,0x16(%rax)
  40e4ad:	0f 84 35 14 00 00    	je     40f8e8 <process_udp.isra.0+0x2d28>
  40e4b3:	4c 8d ad 16 f2 ff ff 	lea    -0xdea(%rbp),%r13
  40e4ba:	4c 89 ef             	mov    %r13,%rdi
  40e4bd:	e8 de 66 ff ff       	call   404ba0 <is_multi_broadcast>
  40e4c2:	80 bd 87 f0 ff ff 00 	cmpb   $0x0,-0xf79(%rbp)
  40e4c9:	41 89 c4             	mov    %eax,%r12d
  40e4cc:	0f 85 6d 04 00 00    	jne    40e93f <process_udp.isra.0+0x1d7f>
  40e4d2:	48 8d bd 30 f3 ff ff 	lea    -0xcd0(%rbp),%rdi
  40e4d9:	4c 89 ee             	mov    %r13,%rsi
  40e4dc:	e8 1f 64 ff ff       	call   404900 <macaddr_str>
  40e4e1:	48 8b b5 60 f0 ff ff 	mov    -0xfa0(%rbp),%rsi
  40e4e8:	48 8d bd f0 f2 ff ff 	lea    -0xd10(%rbp),%rdi
  40e4ef:	49 89 c6             	mov    %rax,%r14
  40e4f2:	e8 09 64 ff ff       	call   404900 <macaddr_str>
  40e4f7:	49 89 c1             	mov    %rax,%r9
  40e4fa:	45 84 e4             	test   %r12b,%r12b
  40e4fd:	0f 85 b0 18 00 00    	jne    40fdb3 <process_udp.isra.0+0x31f3>
  40e503:	48 8d 05 68 65 01 00 	lea    0x16568(%rip),%rax        # 424a72 <_IO_stdin_used+0x3a72>
  40e50a:	4c 8d 05 af 66 01 00 	lea    0x166af(%rip),%r8        # 424bc0 <_IO_stdin_used+0x3bc0>
  40e511:	50                   	push   %rax
  40e512:	41 56                	push   %r14
  40e514:	31 c0                	xor    %eax,%eax
  40e516:	48 8d 0d 88 66 01 00 	lea    0x16688(%rip),%rcx        # 424ba5 <_IO_stdin_used+0x3ba5>
  40e51d:	ba d2 06 00 00       	mov    $0x6d2,%edx
  40e522:	bf 04 00 00 00       	mov    $0x4,%edi
  40e527:	48 8d 35 c7 63 01 00 	lea    0x163c7(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40e52e:	4c 8d b5 c0 f7 ff ff 	lea    -0x840(%rbp),%r14
  40e535:	e8 36 5e ff ff       	call   404370 <_traceEvent>
  40e53a:	58                   	pop    %rax
  40e53b:	48 8b 85 30 f1 ff ff 	mov    -0xed0(%rbp),%rax
  40e542:	4c 89 f7             	mov    %r14,%rdi
  40e545:	5a                   	pop    %rdx
  40e546:	66 0f 6f 9d 20 f1 ff 	movdqa -0xee0(%rbp),%xmm3
  40e54d:	ff 
  40e54e:	48 8d b5 f8 f0 ff ff 	lea    -0xf08(%rbp),%rsi
  40e555:	48 8d 95 a0 f1 ff ff 	lea    -0xe60(%rbp),%rdx
  40e55c:	66 0f 6f a5 00 f1 ff 	movdqa -0xf00(%rbp),%xmm4
  40e563:	ff 
  40e564:	48 89 85 b0 f1 ff ff 	mov    %rax,-0xe50(%rbp)
  40e56b:	48 8b 8d 60 f0 ff ff 	mov    -0xfa0(%rbp),%rcx
  40e572:	8b 85 10 f1 ff ff    	mov    -0xef0(%rbp),%eax
  40e578:	0f 29 9d a0 f1 ff ff 	movaps %xmm3,-0xe60(%rbp)
  40e57f:	48 89 b5 b0 f0 ff ff 	mov    %rsi,-0xf50(%rbp)
  40e586:	66 83 8d a2 f1 ff ff 	orw    $0x60,-0xe5e(%rbp)
  40e58d:	60 
  40e58e:	0f 11 a5 1c f2 ff ff 	movups %xmm4,-0xde4(%rbp)
  40e595:	89 85 2c f2 ff ff    	mov    %eax,-0xdd4(%rbp)
  40e59b:	e8 00 c7 00 00       	call   41aca0 <encode_PACKET>
  40e5a0:	48 8b 85 e0 f0 ff ff 	mov    -0xf20(%rbp),%rax
  40e5a7:	4c 89 f7             	mov    %r14,%rdi
  40e5aa:	48 8b 8d c0 f0 ff ff 	mov    -0xf40(%rbp),%rcx
  40e5b1:	48 8b 95 b8 f0 ff ff 	mov    -0xf48(%rbp),%rdx
  40e5b8:	48 8b b5 b0 f0 ff ff 	mov    -0xf50(%rbp),%rsi
  40e5bf:	48 29 c1             	sub    %rax,%rcx
  40e5c2:	48 8b 9d f8 f0 ff ff 	mov    -0xf08(%rbp),%rbx
  40e5c9:	48 01 c2             	add    %rax,%rdx
  40e5cc:	e8 0f ae 00 00       	call   4193e0 <encode_buf>
  40e5d1:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40e5d8:	80 78 16 02          	cmpb   $0x2,0x16(%rax)
  40e5dc:	0f 84 bb 21 00 00    	je     41079d <process_udp.isra.0+0x3bdd>
  40e5e2:	48 8b 85 f8 f0 ff ff 	mov    -0xf08(%rbp),%rax
  40e5e9:	4c 89 b5 b8 f0 ff ff 	mov    %r14,-0xf48(%rbp)
  40e5f0:	48 89 85 c0 f0 ff ff 	mov    %rax,-0xf40(%rbp)
  40e5f7:	0f b6 8d 87 f0 ff ff 	movzbl -0xf79(%rbp),%ecx
  40e5fe:	45 84 e4             	test   %r12b,%r12b
  40e601:	0f 85 e1 10 00 00    	jne    40f6e8 <process_udp.isra.0+0x2b28>
  40e607:	48 83 ec 08          	sub    $0x8,%rsp
  40e60b:	ff 75 10             	push   0x10(%rbp)
  40e60e:	4c 8b 8d c0 f0 ff ff 	mov    -0xf40(%rbp),%r9
  40e615:	4c 89 ea             	mov    %r13,%rdx
  40e618:	4c 8b 85 b8 f0 ff ff 	mov    -0xf48(%rbp),%r8
  40e61f:	48 8b b5 c8 f0 ff ff 	mov    -0xf38(%rbp),%rsi
  40e626:	48 8b bd 98 f0 ff ff 	mov    -0xf68(%rbp),%rdi
  40e62d:	e8 4e b1 ff ff       	call   409780 <try_forward.isra.0>
  40e632:	41 5d                	pop    %r13
  40e634:	41 5e                	pop    %r14
  40e636:	e9 64 e7 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40e63b:	48 83 bd c8 f0 ff ff 	cmpq   $0x0,-0xf38(%rbp)
  40e642:	00 
  40e643:	48 c7 85 f8 f0 ff ff 	movq   $0x0,-0xf08(%rbp)
  40e64a:	00 00 00 00 
  40e64e:	0f 84 ba 28 00 00    	je     410f0e <process_udp.isra.0+0x434e>
  40e654:	48 8b 85 98 f0 ff ff 	mov    -0xf68(%rbp),%rax
  40e65b:	48 8b 75 10          	mov    0x10(%rbp),%rsi
  40e65f:	4c 89 e1             	mov    %r12,%rcx
  40e662:	4c 8b 85 90 f0 ff ff 	mov    -0xf70(%rbp),%r8
  40e669:	48 8b 95 b8 f0 ff ff 	mov    -0xf48(%rbp),%rdx
  40e670:	48 89 70 50          	mov    %rsi,0x50(%rax)
  40e674:	48 8d 85 10 f2 ff ff 	lea    -0xdf0(%rbp),%rax
  40e67b:	48 8b b5 88 f0 ff ff 	mov    -0xf78(%rbp),%rsi
  40e682:	48 89 c7             	mov    %rax,%rdi
  40e685:	48 89 85 60 f0 ff ff 	mov    %rax,-0xfa0(%rbp)
  40e68c:	e8 6f b4 00 00       	call   419b00 <decode_REGISTER>
  40e691:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40e698:	80 78 16 02          	cmpb   $0x2,0x16(%rax)
  40e69c:	0f 84 ff 12 00 00    	je     40f9a1 <process_udp.isra.0+0x2de1>
  40e6a2:	4c 8d a5 1a f2 ff ff 	lea    -0xde6(%rbp),%r12
  40e6a9:	4c 89 e7             	mov    %r12,%rdi
  40e6ac:	e8 ef 64 ff ff       	call   404ba0 <is_multi_broadcast>
  40e6b1:	84 c0                	test   %al,%al
  40e6b3:	0f 85 c7 12 00 00    	jne    40f980 <process_udp.isra.0+0x2dc0>
  40e6b9:	f6 85 22 f1 ff ff 20 	testb  $0x20,-0xede(%rbp)
  40e6c0:	48 8d 05 a3 63 01 00 	lea    0x163a3(%rip),%rax        # 424a6a <_IO_stdin_used+0x3a6a>
  40e6c7:	4c 89 e6             	mov    %r12,%rsi
  40e6ca:	48 8d bd 30 f3 ff ff 	lea    -0xcd0(%rbp),%rdi
  40e6d1:	4c 8d 35 9a 63 01 00 	lea    0x1639a(%rip),%r14        # 424a72 <_IO_stdin_used+0x3a72>
  40e6d8:	4c 0f 45 f0          	cmovne %rax,%r14
  40e6dc:	e8 1f 62 ff ff       	call   404900 <macaddr_str>
  40e6e1:	48 8d b5 14 f2 ff ff 	lea    -0xdec(%rbp),%rsi
  40e6e8:	48 8d bd f0 f2 ff ff 	lea    -0xd10(%rbp),%rdi
  40e6ef:	48 89 c3             	mov    %rax,%rbx
  40e6f2:	e8 09 62 ff ff       	call   404900 <macaddr_str>
  40e6f7:	48 83 ec 08          	sub    $0x8,%rsp
  40e6fb:	49 89 d9             	mov    %rbx,%r9
  40e6fe:	48 8d 0d 98 63 01 00 	lea    0x16398(%rip),%rcx        # 424a9d <_IO_stdin_used+0x3a9d>
  40e705:	41 56                	push   %r14
  40e707:	49 89 c0             	mov    %rax,%r8
  40e70a:	ba 26 07 00 00       	mov    $0x726,%edx
  40e70f:	31 c0                	xor    %eax,%eax
  40e711:	48 8d 35 dd 61 01 00 	lea    0x161dd(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40e718:	bf 04 00 00 00       	mov    $0x4,%edi
  40e71d:	e8 4e 5c ff ff       	call   404370 <_traceEvent>
  40e722:	0f b7 85 22 f1 ff ff 	movzwl -0xede(%rbp),%eax
  40e729:	41 5a                	pop    %r10
  40e72b:	41 5b                	pop    %r11
  40e72d:	a8 20                	test   $0x20,%al
  40e72f:	0f 84 53 08 00 00    	je     40ef88 <process_udp.isra.0+0x23c8>
  40e735:	48 8b 85 c0 f0 ff ff 	mov    -0xf40(%rbp),%rax
  40e73c:	48 89 85 f8 f0 ff ff 	mov    %rax,-0xf08(%rbp)
  40e743:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40e74a:	80 78 16 02          	cmpb   $0x2,0x16(%rax)
  40e74e:	0f 84 22 1e 00 00    	je     410576 <process_udp.isra.0+0x39b6>
  40e754:	48 83 ec 08          	sub    $0x8,%rsp
  40e758:	0f b6 8d 87 f0 ff ff 	movzbl -0xf79(%rbp),%ecx
  40e75f:	ff 75 10             	push   0x10(%rbp)
  40e762:	4c 89 e2             	mov    %r12,%rdx
  40e765:	4c 8b 8d f8 f0 ff ff 	mov    -0xf08(%rbp),%r9
  40e76c:	4c 8b 85 b8 f0 ff ff 	mov    -0xf48(%rbp),%r8
  40e773:	48 8b b5 c8 f0 ff ff 	mov    -0xf38(%rbp),%rsi
  40e77a:	48 8b bd 98 f0 ff ff 	mov    -0xf68(%rbp),%rdi
  40e781:	e8 fa af ff ff       	call   409780 <try_forward.isra.0>
  40e786:	41 58                	pop    %r8
  40e788:	41 59                	pop    %r9
  40e78a:	e9 10 e6 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40e78f:	48 8d 0d e2 62 01 00 	lea    0x162e2(%rip),%rcx        # 424a78 <_IO_stdin_used+0x3a78>
  40e796:	ba ad 06 00 00       	mov    $0x6ad,%edx
  40e79b:	bf 01 00 00 00       	mov    $0x1,%edi
  40e7a0:	48 8d 35 4e 61 01 00 	lea    0x1614e(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40e7a7:	e8 c4 5b ff ff       	call   404370 <_traceEvent>
  40e7ac:	e9 ee e5 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40e7b1:	4c 8d a5 f0 f2 ff ff 	lea    -0xd10(%rbp),%r12
  40e7b8:	4c 89 fe             	mov    %r15,%rsi
  40e7bb:	48 8d 9d 10 f2 ff ff 	lea    -0xdf0(%rbp),%rbx
  40e7c2:	4c 89 e7             	mov    %r12,%rdi
  40e7c5:	e8 36 61 ff ff       	call   404900 <macaddr_str>
  40e7ca:	ba 73 09 00 00       	mov    $0x973,%edx
  40e7cf:	bf 04 00 00 00       	mov    $0x4,%edi
  40e7d4:	48 8d 0d 58 63 01 00 	lea    0x16358(%rip),%rcx        # 424b33 <_IO_stdin_used+0x3b33>
  40e7db:	49 89 c0             	mov    %rax,%r8
  40e7de:	48 8d 35 10 61 01 00 	lea    0x16110(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40e7e5:	31 c0                	xor    %eax,%eax
  40e7e7:	e8 84 5b ff ff       	call   404370 <_traceEvent>
  40e7ec:	8b 85 34 f1 ff ff    	mov    -0xecc(%rbp),%eax
  40e7f2:	45 31 db             	xor    %r11d,%r11d
  40e7f5:	4c 8b b5 98 f0 ff ff 	mov    -0xf68(%rbp),%r14
  40e7fc:	f3 0f 6f a5 24 f1 ff 	movdqu -0xedc(%rbp),%xmm4
  40e803:	ff 
  40e804:	66 0f 6f ad 00 f1 ff 	movdqa -0xf00(%rbp),%xmm5
  40e80b:	ff 
  40e80c:	66 44 89 9d 10 f2 ff 	mov    %r11w,-0xdf0(%rbp)
  40e813:	ff 
  40e814:	89 85 74 f1 ff ff    	mov    %eax,-0xe8c(%rbp)
  40e81a:	8b 85 bc f1 ff ff    	mov    -0xe44(%rbp),%eax
  40e820:	4c 89 f7             	mov    %r14,%rdi
  40e823:	0f 11 a5 64 f1 ff ff 	movups %xmm4,-0xe9c(%rbp)
  40e82a:	89 85 18 f2 ff ff    	mov    %eax,-0xde8(%rbp)
  40e830:	0f b7 85 c0 f1 ff ff 	movzwl -0xe40(%rbp),%eax
  40e837:	0f 11 ad 1e f2 ff ff 	movups %xmm5,-0xde2(%rbp)
  40e83e:	66 89 85 1c f2 ff ff 	mov    %ax,-0xde4(%rbp)
  40e845:	41 8b 46 64          	mov    0x64(%r14),%eax
  40e849:	c7 85 60 f1 ff ff 02 	movl   $0x200a02,-0xea0(%rbp)
  40e850:	0a 20 00 
  40e853:	89 85 12 f2 ff ff    	mov    %eax,-0xdee(%rbp)
  40e859:	41 0f b7 46 68       	movzwl 0x68(%r14),%eax
  40e85e:	66 89 85 16 f2 ff ff 	mov    %ax,-0xdea(%rbp)
  40e865:	8b 85 10 f1 ff ff    	mov    -0xef0(%rbp),%eax
  40e86b:	89 85 2e f2 ff ff    	mov    %eax,-0xdd2(%rbp)
  40e871:	e8 7a 8b ff ff       	call   4073f0 <sn_selection_criterion_gather_data>
  40e876:	49 8d 4e 10          	lea    0x10(%r14),%rcx
  40e87a:	be 14 00 00 00       	mov    $0x14,%esi
  40e87f:	48 8d bd 4c f2 ff ff 	lea    -0xdb4(%rbp),%rdi
  40e886:	89 85 48 f2 ff ff    	mov    %eax,-0xdb8(%rbp)
  40e88c:	48 8d 15 e3 60 01 00 	lea    0x160e3(%rip),%rdx        # 424976 <_IO_stdin_used+0x3976>
  40e893:	31 c0                	xor    %eax,%eax
  40e895:	e8 76 3d ff ff       	call   402610 <snprintf@plt>
  40e89a:	48 8b 45 10          	mov    0x10(%rbp),%rax
  40e89e:	49 2b 46 08          	sub    0x8(%r14),%rax
  40e8a2:	48 89 d9             	mov    %rbx,%rcx
  40e8a5:	48 89 85 60 f2 ff ff 	mov    %rax,-0xda0(%rbp)
  40e8ac:	48 8d 85 c0 f7 ff ff 	lea    -0x840(%rbp),%rax
  40e8b3:	48 8d 95 60 f1 ff ff 	lea    -0xea0(%rbp),%rdx
  40e8ba:	48 8d b5 f8 f0 ff ff 	lea    -0xf08(%rbp),%rsi
  40e8c1:	48 89 c7             	mov    %rax,%rdi
  40e8c4:	48 89 85 c0 f0 ff ff 	mov    %rax,-0xf40(%rbp)
  40e8cb:	e8 a0 c5 00 00       	call   41ae70 <encode_PEER_INFO>
  40e8d0:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40e8d7:	48 85 c0             	test   %rax,%rax
  40e8da:	74 0a                	je     40e8e6 <process_udp.isra.0+0x1d26>
  40e8dc:	80 78 16 02          	cmpb   $0x2,0x16(%rax)
  40e8e0:	0f 84 2e 1f 00 00    	je     410814 <process_udp.isra.0+0x3c54>
  40e8e6:	4c 8b 85 f8 f0 ff ff 	mov    -0xf08(%rbp),%r8
  40e8ed:	48 8b 8d c0 f0 ff ff 	mov    -0xf40(%rbp),%rcx
  40e8f4:	48 8b 95 78 f0 ff ff 	mov    -0xf88(%rbp),%rdx
  40e8fb:	8b b5 80 f0 ff ff    	mov    -0xf80(%rbp),%esi
  40e901:	48 8b bd 98 f0 ff ff 	mov    -0xf68(%rbp),%rdi
  40e908:	e8 33 a6 ff ff       	call   408f40 <sendto_sock>
  40e90d:	4c 89 fe             	mov    %r15,%rsi
  40e910:	4c 89 e7             	mov    %r12,%rdi
  40e913:	e8 e8 5f ff ff       	call   404900 <macaddr_str>
  40e918:	ba 92 09 00 00       	mov    $0x992,%edx
  40e91d:	bf 04 00 00 00       	mov    $0x4,%edi
  40e922:	48 8d 0d 1a 62 01 00 	lea    0x1621a(%rip),%rcx        # 424b43 <_IO_stdin_used+0x3b43>
  40e929:	49 89 c0             	mov    %rax,%r8
  40e92c:	48 8d 35 c2 5f 01 00 	lea    0x15fc2(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40e933:	31 c0                	xor    %eax,%eax
  40e935:	e8 36 5a ff ff       	call   404370 <_traceEvent>
  40e93a:	e9 60 e4 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40e93f:	48 8d bd 30 f3 ff ff 	lea    -0xcd0(%rbp),%rdi
  40e946:	4c 89 ee             	mov    %r13,%rsi
  40e949:	e8 b2 5f ff ff       	call   404900 <macaddr_str>
  40e94e:	48 8b b5 60 f0 ff ff 	mov    -0xfa0(%rbp),%rsi
  40e955:	48 8d bd f0 f2 ff ff 	lea    -0xd10(%rbp),%rdi
  40e95c:	49 89 c6             	mov    %rax,%r14
  40e95f:	e8 9c 5f ff ff       	call   404900 <macaddr_str>
  40e964:	49 89 c1             	mov    %rax,%r9
  40e967:	45 84 e4             	test   %r12b,%r12b
  40e96a:	0f 85 ee 13 00 00    	jne    40fd5e <process_udp.isra.0+0x319e>
  40e970:	48 8d 05 f3 60 01 00 	lea    0x160f3(%rip),%rax        # 424a6a <_IO_stdin_used+0x3a6a>
  40e977:	4c 8d 05 42 62 01 00 	lea    0x16242(%rip),%r8        # 424bc0 <_IO_stdin_used+0x3bc0>
  40e97e:	50                   	push   %rax
  40e97f:	41 56                	push   %r14
  40e981:	31 c0                	xor    %eax,%eax
  40e983:	48 8d 0d 1b 62 01 00 	lea    0x1621b(%rip),%rcx        # 424ba5 <_IO_stdin_used+0x3ba5>
  40e98a:	ba d2 06 00 00       	mov    $0x6d2,%edx
  40e98f:	bf 04 00 00 00       	mov    $0x4,%edi
  40e994:	48 8d 35 5a 5f 01 00 	lea    0x15f5a(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40e99b:	e8 d0 59 ff ff       	call   404370 <_traceEvent>
  40e9a0:	59                   	pop    %rcx
  40e9a1:	31 c0                	xor    %eax,%eax
  40e9a3:	5e                   	pop    %rsi
  40e9a4:	48 8d 0d d9 60 01 00 	lea    0x160d9(%rip),%rcx        # 424a84 <_IO_stdin_used+0x3a84>
  40e9ab:	ba f3 06 00 00       	mov    $0x6f3,%edx
  40e9b0:	48 8d 35 3e 5f 01 00 	lea    0x15f3e(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40e9b7:	bf 04 00 00 00       	mov    $0x4,%edi
  40e9bc:	e8 af 59 ff ff       	call   404370 <_traceEvent>
  40e9c1:	48 8b 85 c0 f0 ff ff 	mov    -0xf40(%rbp),%rax
  40e9c8:	48 89 85 f8 f0 ff ff 	mov    %rax,-0xf08(%rbp)
  40e9cf:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40e9d6:	80 78 16 02          	cmpb   $0x2,0x16(%rax)
  40e9da:	0f 85 17 fc ff ff    	jne    40e5f7 <process_udp.isra.0+0x1a37>
  40e9e0:	e8 4b 6e ff ff       	call   405830 <time_stamp>
  40e9e5:	48 8b 95 f8 f0 ff ff 	mov    -0xf08(%rbp),%rdx
  40e9ec:	be 10 00 00 00       	mov    $0x10,%esi
  40e9f1:	48 8b 9d c8 f0 ff ff 	mov    -0xf38(%rbp),%rbx
  40e9f8:	49 89 c1             	mov    %rax,%r9
  40e9fb:	48 8b 85 e0 f0 ff ff 	mov    -0xf20(%rbp),%rax
  40ea02:	0f b7 fa             	movzwl %dx,%edi
  40ea05:	48 8b 4b 20          	mov    0x20(%rbx),%rcx
  40ea09:	4c 8b 43 30          	mov    0x30(%rbx),%r8
  40ea0d:	48 29 c2             	sub    %rax,%rdx
  40ea10:	48 39 f2             	cmp    %rsi,%rdx
  40ea13:	48 0f 47 d6          	cmova  %rsi,%rdx
  40ea17:	31 f6                	xor    %esi,%esi
  40ea19:	48 83 7b 58 00       	cmpq   $0x0,0x58(%rbx)
  40ea1e:	0f 45 f2             	cmovne %edx,%esi
  40ea21:	89 fa                	mov    %edi,%edx
  40ea23:	48 8b bd b8 f0 ff ff 	mov    -0xf48(%rbp),%rdi
  40ea2a:	01 c6                	add    %eax,%esi
  40ea2c:	0f b7 f6             	movzwl %si,%esi
  40ea2f:	e8 1c f8 00 00       	call   41e250 <packet_header_encrypt>
  40ea34:	48 8b 85 f8 f0 ff ff 	mov    -0xf08(%rbp),%rax
  40ea3b:	48 89 85 c0 f0 ff ff 	mov    %rax,-0xf40(%rbp)
  40ea42:	e9 b0 fb ff ff       	jmp    40e5f7 <process_udp.isra.0+0x1a37>
  40ea47:	48 8b 85 98 f0 ff ff 	mov    -0xf68(%rbp),%rax
  40ea4e:	8b 98 a4 00 00 00    	mov    0xa4(%rax),%ebx
  40ea54:	85 db                	test   %ebx,%ebx
  40ea56:	0f 84 c3 0c 00 00    	je     40f71f <process_udp.isra.0+0x2b5f>
  40ea5c:	48 8b 80 b8 00 00 00 	mov    0xb8(%rax),%rax
  40ea63:	4c 8d b5 24 f1 ff ff 	lea    -0xedc(%rbp),%r14
  40ea6a:	48 85 c0             	test   %rax,%rax
  40ea6d:	0f 84 5f 07 00 00    	je     40f1d2 <process_udp.isra.0+0x2612>
  40ea73:	4c 8b 78 18          	mov    0x18(%rax),%r15
  40ea77:	4c 8d b5 24 f1 ff ff 	lea    -0xedc(%rbp),%r14
  40ea7e:	4c 8d ad f0 f0 ff ff 	lea    -0xf10(%rbp),%r13
  40ea85:	48 8b 38             	mov    (%rax),%rdi
  40ea88:	4c 89 ea             	mov    %r13,%rdx
  40ea8b:	4c 89 f6             	mov    %r14,%rsi
  40ea8e:	e8 1d 07 01 00       	call   41f1b0 <re_matchp>
  40ea93:	89 c3                	mov    %eax,%ebx
  40ea95:	3c ff                	cmp    $0xff,%al
  40ea97:	74 1c                	je     40eab5 <process_udp.isra.0+0x1ef5>
  40ea99:	4c 89 f7             	mov    %r14,%rdi
  40ea9c:	e8 0f 3b ff ff       	call   4025b0 <strlen@plt>
  40eaa1:	48 63 95 f0 f0 ff ff 	movslq -0xf10(%rbp),%rdx
  40eaa8:	48 39 c2             	cmp    %rax,%rdx
  40eaab:	75 08                	jne    40eab5 <process_udp.isra.0+0x1ef5>
  40eaad:	84 db                	test   %bl,%bl
  40eaaf:	0f 84 6a 0c 00 00    	je     40f71f <process_udp.isra.0+0x2b5f>
  40eab5:	4d 85 ff             	test   %r15,%r15
  40eab8:	0f 84 14 07 00 00    	je     40f1d2 <process_udp.isra.0+0x2612>
  40eabe:	4c 89 f8             	mov    %r15,%rax
  40eac1:	4d 8b 7f 18          	mov    0x18(%r15),%r15
  40eac5:	eb be                	jmp    40ea85 <process_udp.isra.0+0x1ec5>
  40eac7:	48 8d 0d 0a 49 01 00 	lea    0x1490a(%rip),%rcx        # 4233d8 <_IO_stdin_used+0x23d8>
  40eace:	ba fe 08 00 00       	mov    $0x8fe,%edx
  40ead3:	48 8d 35 1b 5e 01 00 	lea    0x15e1b(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40eada:	31 c0                	xor    %eax,%eax
  40eadc:	bf 03 00 00 00       	mov    $0x3,%edi
  40eae1:	e8 8a 58 ff ff       	call   404370 <_traceEvent>
  40eae6:	e9 b4 e2 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40eaeb:	48 8d 0d 36 46 01 00 	lea    0x14636(%rip),%rcx        # 423128 <_IO_stdin_used+0x2128>
  40eaf2:	ba b2 07 00 00       	mov    $0x7b2,%edx
  40eaf7:	48 8d 35 f7 5d 01 00 	lea    0x15df7(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40eafe:	31 c0                	xor    %eax,%eax
  40eb00:	bf 03 00 00 00       	mov    $0x3,%edi
  40eb05:	e8 66 58 ff ff       	call   404370 <_traceEvent>
  40eb0a:	45 31 d2             	xor    %r10d,%r10d
  40eb0d:	48 8b b5 98 f0 ff ff 	mov    -0xf68(%rbp),%rsi
  40eb14:	48 8d 46 64          	lea    0x64(%rsi),%rax
  40eb18:	8b 76 64             	mov    0x64(%rsi),%esi
  40eb1b:	39 b5 14 f2 ff ff    	cmp    %esi,-0xdec(%rbp)
  40eb21:	0f 84 74 0c 00 00    	je     40f79b <process_udp.isra.0+0x2bdb>
  40eb27:	8b 85 34 f1 ff ff    	mov    -0xecc(%rbp),%eax
  40eb2d:	48 8b b5 98 f0 ff ff 	mov    -0xf68(%rbp),%rsi
  40eb34:	c7 85 40 f1 ff ff 02 	movl   $0x600702,-0xec0(%rbp)
  40eb3b:	07 60 00 
  40eb3e:	f3 0f 6f 8d 24 f1 ff 	movdqu -0xedc(%rbp),%xmm1
  40eb45:	ff 
  40eb46:	89 85 54 f1 ff ff    	mov    %eax,-0xeac(%rbp)
  40eb4c:	8b 85 10 f2 ff ff    	mov    -0xdf0(%rbp),%eax
  40eb52:	0f 11 8d 44 f1 ff ff 	movups %xmm1,-0xebc(%rbp)
  40eb59:	89 85 a0 f1 ff ff    	mov    %eax,-0xe60(%rbp)
  40eb5f:	8b 46 64             	mov    0x64(%rsi),%eax
  40eb62:	89 85 a4 f1 ff ff    	mov    %eax,-0xe5c(%rbp)
  40eb68:	0f b7 46 68          	movzwl 0x68(%rsi),%eax
  40eb6c:	66 89 85 a8 f1 ff ff 	mov    %ax,-0xe58(%rbp)
  40eb73:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40eb7a:	80 78 14 01          	cmpb   $0x1,0x14(%rax)
  40eb7e:	74 2d                	je     40ebad <process_udp.isra.0+0x1fed>
  40eb80:	8b 85 30 f2 ff ff    	mov    -0xdd0(%rbp),%eax
  40eb86:	8d 50 ff             	lea    -0x1(%rax),%edx
  40eb89:	83 fa fd             	cmp    $0xfffffffd,%edx
  40eb8c:	0f 87 67 06 00 00    	ja     40f1f9 <process_udp.isra.0+0x2639>
  40eb92:	80 bd 34 f2 ff ff 00 	cmpb   $0x0,-0xdcc(%rbp)
  40eb99:	0f 84 5a 06 00 00    	je     40f1f9 <process_udp.isra.0+0x2639>
  40eb9f:	66 31 c0             	xor    %ax,%ax
  40eba2:	3d 00 00 fe a9       	cmp    $0xa9fe0000,%eax
  40eba7:	0f 84 4c 06 00 00    	je     40f1f9 <process_udp.isra.0+0x2639>
  40ebad:	8b 85 10 f1 ff ff    	mov    -0xef0(%rbp),%eax
  40ebb3:	66 0f 6f 95 00 f1 ff 	movdqa -0xf00(%rbp),%xmm2
  40ebba:	ff 
  40ebbb:	b9 0f 00 00 00       	mov    $0xf,%ecx
  40ebc0:	4c 8d bd 14 f2 ff ff 	lea    -0xdec(%rbp),%r15
  40ebc7:	66 89 8d b4 f1 ff ff 	mov    %cx,-0xe4c(%rbp)
  40ebce:	89 85 c6 f1 ff ff    	mov    %eax,-0xe3a(%rbp)
  40ebd4:	48 8d 85 b6 f1 ff ff 	lea    -0xe4a(%rbp),%rax
  40ebdb:	48 89 85 48 f0 ff ff 	mov    %rax,-0xfb8(%rbp)
  40ebe2:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40ebe9:	0f 11 95 b6 f1 ff ff 	movups %xmm2,-0xe4a(%rbp)
  40ebf0:	80 78 14 01          	cmpb   $0x1,0x14(%rax)
  40ebf4:	0f 84 64 12 00 00    	je     40fe5e <process_udp.isra.0+0x329e>
  40ebfa:	4c 8b b5 98 f0 ff ff 	mov    -0xf68(%rbp),%r14
  40ec01:	49 8b 86 c0 00 00 00 	mov    0xc0(%r14),%rax
  40ec08:	48 8b 58 48          	mov    0x48(%rax),%rbx
  40ec0c:	48 85 db             	test   %rbx,%rbx
  40ec0f:	0f 84 05 0e 00 00    	je     40fa1a <process_udp.isra.0+0x2e5a>
  40ec15:	48 8b 83 e8 00 00 00 	mov    0xe8(%rbx),%rax
  40ec1c:	45 31 c9             	xor    %r9d,%r9d
  40ec1f:	8b 40 10             	mov    0x10(%rax),%eax
  40ec22:	83 e8 01             	sub    $0x1,%eax
  40ec25:	89 c7                	mov    %eax,%edi
  40ec27:	0f 89 c3 0d 00 00    	jns    40f9f0 <process_udp.isra.0+0x2e30>
  40ec2d:	41 b8 8e 04 00 00    	mov    $0x48e,%r8d
  40ec33:	4c 89 bd 58 f0 ff ff 	mov    %r15,-0xfa8(%rbp)
  40ec3a:	4c 8b a3 f8 00 00 00 	mov    0xf8(%rbx),%r12
  40ec41:	4c 8d b5 30 f3 ff ff 	lea    -0xcd0(%rbp),%r14
  40ec48:	4d 89 c7             	mov    %r8,%r15
  40ec4b:	4c 89 95 a0 f0 ff ff 	mov    %r10,-0xf60(%rbp)
  40ec52:	45 31 db             	xor    %r11d,%r11d
  40ec55:	4c 8b 85 48 f0 ff ff 	mov    -0xfb8(%rbp),%r8
  40ec5c:	45 85 c9             	test   %r9d,%r9d
  40ec5f:	0f 85 22 01 00 00    	jne    40ed87 <process_udp.isra.0+0x21c7>
  40ec65:	0f 1f 00             	nopl   (%rax)
  40ec68:	80 7b 20 ff          	cmpb   $0xff,0x20(%rbx)
  40ec6c:	0f 84 fc 00 00 00    	je     40ed6e <process_udp.isra.0+0x21ae>
  40ec72:	48 8b 43 20          	mov    0x20(%rbx),%rax
  40ec76:	48 8b 53 28          	mov    0x28(%rbx),%rdx
  40ec7a:	48 8d 4b 20          	lea    0x20(%rbx),%rcx
  40ec7e:	49 33 00             	xor    (%r8),%rax
  40ec81:	49 33 50 08          	xor    0x8(%r8),%rdx
  40ec85:	48 09 d0             	or     %rdx,%rax
  40ec88:	0f 84 32 05 00 00    	je     40f1c0 <process_udp.isra.0+0x2600>
  40ec8e:	48 8b 45 10          	mov    0x10(%rbp),%rax
  40ec92:	48 2b 83 90 00 00 00 	sub    0x90(%rbx),%rax
  40ec99:	48 83 f8 3b          	cmp    $0x3b,%rax
  40ec9d:	0f 8f cb 00 00 00    	jg     40ed6e <process_udp.isra.0+0x21ae>
  40eca3:	41 83 c3 01          	add    $0x1,%r11d
  40eca7:	49 63 c3             	movslq %r11d,%rax
  40ecaa:	48 8d 14 40          	lea    (%rax,%rax,2),%rdx
  40ecae:	48 8d 04 90          	lea    (%rax,%rdx,4),%rax
  40ecb2:	48 01 c0             	add    %rax,%rax
  40ecb5:	48 3d 8e 04 00 00    	cmp    $0x48e,%rax
  40ecbb:	0f 87 cf 00 00 00    	ja     40ed90 <process_udp.isra.0+0x21d0>
  40ecc1:	48 8b b5 90 f0 ff ff 	mov    -0xf70(%rbp),%rsi
  40ecc8:	48 89 ca             	mov    %rcx,%rdx
  40eccb:	4c 89 f7             	mov    %r14,%rdi
  40ecce:	41 bd 8e 04 00 00    	mov    $0x48e,%r13d
  40ecd4:	4c 89 85 a8 f0 ff ff 	mov    %r8,-0xf58(%rbp)
  40ecdb:	44 89 8d b0 f0 ff ff 	mov    %r9d,-0xf50(%rbp)
  40ece2:	44 89 9d b8 f0 ff ff 	mov    %r11d,-0xf48(%rbp)
  40ece9:	48 c7 85 e0 f0 ff ff 	movq   $0x0,-0xf20(%rbp)
  40ecf0:	00 00 00 00 
  40ecf4:	e8 97 ab 00 00       	call   419890 <encode_sock_payload>
  40ecf9:	4d 39 ef             	cmp    %r13,%r15
  40ecfc:	ba 14 00 00 00       	mov    $0x14,%edx
  40ed01:	48 89 de             	mov    %rbx,%rsi
  40ed04:	4d 0f 43 ef          	cmovae %r15,%r13
  40ed08:	49 8d 7e 14          	lea    0x14(%r14),%rdi
  40ed0c:	4d 89 ea             	mov    %r13,%r10
  40ed0f:	4d 29 fa             	sub    %r15,%r10
  40ed12:	4d 29 ef             	sub    %r13,%r15
  40ed15:	4c 89 d0             	mov    %r10,%rax
  40ed18:	4d 39 d5             	cmp    %r10,%r13
  40ed1b:	4c 89 95 c0 f0 ff ff 	mov    %r10,-0xf40(%rbp)
  40ed22:	49 0f 43 c5          	cmovae %r13,%rax
  40ed26:	4c 01 f8             	add    %r15,%rax
  40ed29:	48 39 d0             	cmp    %rdx,%rax
  40ed2c:	48 0f 42 c2          	cmovb  %rdx,%rax
  40ed30:	ba 06 00 00 00       	mov    $0x6,%edx
  40ed35:	48 8d 48 ec          	lea    -0x14(%rax),%rcx
  40ed39:	e8 a2 39 ff ff       	call   4026e0 <__memcpy_chk@plt>
  40ed3e:	4c 8b 95 c0 f0 ff ff 	mov    -0xf40(%rbp),%r10
  40ed45:	4c 8b 85 a8 f0 ff ff 	mov    -0xf58(%rbp),%r8
  40ed4c:	44 8b 8d b0 f0 ff ff 	mov    -0xf50(%rbp),%r9d
  40ed53:	44 8b 9d b8 f0 ff ff 	mov    -0xf48(%rbp),%r11d
  40ed5a:	49 83 c2 1a          	add    $0x1a,%r10
  40ed5e:	4d 39 ea             	cmp    %r13,%r10
  40ed61:	4d 0f 42 d5          	cmovb  %r13,%r10
  40ed65:	49 83 c6 1a          	add    $0x1a,%r14
  40ed69:	4f 8d 7c 17 e6       	lea    -0x1a(%r15,%r10,1),%r15
  40ed6e:	4d 85 e4             	test   %r12,%r12
  40ed71:	74 1d                	je     40ed90 <process_udp.isra.0+0x21d0>
  40ed73:	4c 89 e3             	mov    %r12,%rbx
  40ed76:	4d 8b a4 24 f8 00 00 	mov    0xf8(%r12),%r12
  40ed7d:	00 
  40ed7e:	45 85 c9             	test   %r9d,%r9d
  40ed81:	0f 84 e1 fe ff ff    	je     40ec68 <process_udp.isra.0+0x20a8>
  40ed87:	41 83 e9 01          	sub    $0x1,%r9d
  40ed8b:	4d 85 e4             	test   %r12,%r12
  40ed8e:	75 e3                	jne    40ed73 <process_udp.isra.0+0x21b3>
  40ed90:	4c 8b 95 a0 f0 ff ff 	mov    -0xf60(%rbp),%r10
  40ed97:	4c 8b bd 58 f0 ff ff 	mov    -0xfa8(%rbp),%r15
  40ed9e:	4c 8b b5 48 f0 ff ff 	mov    -0xfb8(%rbp),%r14
  40eda5:	48 8b bd 70 f0 ff ff 	mov    -0xf90(%rbp),%rdi
  40edac:	4c 8d a5 f0 f2 ff ff 	lea    -0xd10(%rbp),%r12
  40edb3:	4c 89 95 c0 f0 ff ff 	mov    %r10,-0xf40(%rbp)
  40edba:	44 88 9d fe f1 ff ff 	mov    %r11b,-0xe02(%rbp)
  40edc1:	4c 89 f6             	mov    %r14,%rsi
  40edc4:	e8 a7 67 ff ff       	call   405570 <sock_to_cstr>
  40edc9:	4c 89 fe             	mov    %r15,%rsi
  40edcc:	4c 89 e7             	mov    %r12,%rdi
  40edcf:	48 89 c3             	mov    %rax,%rbx
  40edd2:	e8 29 5b ff ff       	call   404900 <macaddr_str>
  40edd7:	48 8d 0d e9 5c 01 00 	lea    0x15ce9(%rip),%rcx        # 424ac7 <_IO_stdin_used+0x3ac7>
  40edde:	49 89 d9             	mov    %rbx,%r9
  40ede1:	ba fa 07 00 00       	mov    $0x7fa,%edx
  40ede6:	49 89 c0             	mov    %rax,%r8
  40ede9:	48 8d 35 05 5b 01 00 	lea    0x15b05(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40edf0:	31 c0                	xor    %eax,%eax
  40edf2:	bf 04 00 00 00       	mov    $0x4,%edi
  40edf7:	e8 74 55 ff ff       	call   404370 <_traceEvent>
  40edfc:	48 8b 8d c8 f0 ff ff 	mov    -0xf38(%rbp),%rcx
  40ee03:	4c 8b 95 c0 f0 ff ff 	mov    -0xf40(%rbp),%r10
  40ee0a:	80 79 14 01          	cmpb   $0x1,0x14(%rcx)
  40ee0e:	74 56                	je     40ee66 <process_udp.isra.0+0x22a6>
  40ee10:	f6 85 22 f1 ff ff 20 	testb  $0x20,-0xede(%rbp)
  40ee17:	0f 84 43 0a 00 00    	je     40f860 <process_udp.isra.0+0x2ca0>
  40ee1d:	48 83 ec 08          	sub    $0x8,%rsp
  40ee21:	48 8d 85 ca f1 ff ff 	lea    -0xe36(%rbp),%rax
  40ee28:	ff 75 10             	push   0x10(%rbp)
  40ee2b:	4d 89 f0             	mov    %r14,%r8
  40ee2e:	44 8b 8d 80 f0 ff ff 	mov    -0xf80(%rbp),%r9d
  40ee35:	6a 01                	push   $0x1
  40ee37:	50                   	push   %rax
  40ee38:	48 8b 95 60 f0 ff ff 	mov    -0xfa0(%rbp),%rdx
  40ee3f:	48 8b b5 88 f0 ff ff 	mov    -0xf78(%rbp),%rsi
  40ee46:	48 8b bd 98 f0 ff ff 	mov    -0xf68(%rbp),%rdi
  40ee4d:	e8 2e 8c ff ff       	call   407a80 <update_edge>
  40ee52:	4c 8b 95 c0 f0 ff ff 	mov    -0xf40(%rbp),%r10
  40ee59:	48 83 c4 20          	add    $0x20,%rsp
  40ee5d:	83 f8 ff             	cmp    $0xffffffff,%eax
  40ee60:	0f 84 03 16 00 00    	je     410469 <process_udp.isra.0+0x38a9>
  40ee66:	0f b7 85 22 f1 ff ff 	movzwl -0xede(%rbp),%eax
  40ee6d:	4c 89 95 c0 f0 ff ff 	mov    %r10,-0xf40(%rbp)
  40ee74:	f7 d0                	not    %eax
  40ee76:	a8 60                	test   $0x60,%al
  40ee78:	0f 84 a4 0b 00 00    	je     40fa22 <process_udp.isra.0+0x2e62>
  40ee7e:	4c 89 ff             	mov    %r15,%rdi
  40ee81:	e8 ba 5d ff ff       	call   404c40 <is_null_mac>
  40ee86:	4c 8b 95 c0 f0 ff ff 	mov    -0xf40(%rbp),%r10
  40ee8d:	84 c0                	test   %al,%al
  40ee8f:	0f 84 e8 12 00 00    	je     41017d <process_udp.isra.0+0x35bd>
  40ee95:	48 8d 85 c0 f7 ff ff 	lea    -0x840(%rbp),%rax
  40ee9c:	48 8d 9d 40 f1 ff ff 	lea    -0xec0(%rbp),%rbx
  40eea3:	48 89 85 c0 f0 ff ff 	mov    %rax,-0xf40(%rbp)
  40eeaa:	4c 8d ad f0 f0 ff ff 	lea    -0xf10(%rbp),%r13
  40eeb1:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40eeb8:	c7 85 00 f2 ff ff 00 	movl   $0x0,-0xe00(%rbp)
  40eebf:	00 00 00 
  40eec2:	80 78 14 01          	cmpb   $0x1,0x14(%rax)
  40eec6:	0f 84 6e 0f 00 00    	je     40fe3a <process_udp.isra.0+0x327a>
  40eecc:	48 8b 8d 50 f0 ff ff 	mov    -0xfb0(%rbp),%rcx
  40eed3:	48 8b bd c0 f0 ff ff 	mov    -0xf40(%rbp),%rdi
  40eeda:	48 89 da             	mov    %rbx,%rdx
  40eedd:	4c 89 ee             	mov    %r13,%rsi
  40eee0:	4c 8d 85 30 f3 ff ff 	lea    -0xcd0(%rbp),%r8
  40eee7:	4c 89 95 b8 f0 ff ff 	mov    %r10,-0xf48(%rbp)
  40eeee:	48 c7 85 f0 f0 ff ff 	movq   $0x0,-0xf10(%rbp)
  40eef5:	00 00 00 00 
  40eef9:	c6 85 41 f1 ff ff 07 	movb   $0x7,-0xebf(%rbp)
  40ef00:	e8 1b b5 00 00       	call   41a420 <encode_REGISTER_SUPER_ACK>
  40ef05:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40ef0c:	80 78 16 02          	cmpb   $0x2,0x16(%rax)
  40ef10:	0f 84 09 18 00 00    	je     41071f <process_udp.isra.0+0x3b5f>
  40ef16:	4c 8b 85 f0 f0 ff ff 	mov    -0xf10(%rbp),%r8
  40ef1d:	48 8b 8d c0 f0 ff ff 	mov    -0xf40(%rbp),%rcx
  40ef24:	48 8b 95 78 f0 ff ff 	mov    -0xf88(%rbp),%rdx
  40ef2b:	8b b5 80 f0 ff ff    	mov    -0xf80(%rbp),%esi
  40ef31:	48 8b bd 98 f0 ff ff 	mov    -0xf68(%rbp),%rdi
  40ef38:	e8 03 a0 ff ff       	call   408f40 <sendto_sock>
  40ef3d:	48 8b b5 48 f0 ff ff 	mov    -0xfb8(%rbp),%rsi
  40ef44:	48 8b bd 70 f0 ff ff 	mov    -0xf90(%rbp),%rdi
  40ef4b:	e8 20 66 ff ff       	call   405570 <sock_to_cstr>
  40ef50:	4c 89 fe             	mov    %r15,%rsi
  40ef53:	4c 89 e7             	mov    %r12,%rdi
  40ef56:	48 89 c3             	mov    %rax,%rbx
  40ef59:	e8 a2 59 ff ff       	call   404900 <macaddr_str>
  40ef5e:	49 89 d9             	mov    %rbx,%r9
  40ef61:	48 8d 0d 60 42 01 00 	lea    0x14260(%rip),%rcx        # 4231c8 <_IO_stdin_used+0x21c8>
  40ef68:	ba 63 08 00 00       	mov    $0x863,%edx
  40ef6d:	49 89 c0             	mov    %rax,%r8
  40ef70:	48 8d 35 7e 59 01 00 	lea    0x1597e(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40ef77:	bf 04 00 00 00       	mov    $0x4,%edi
  40ef7c:	31 c0                	xor    %eax,%eax
  40ef7e:	e8 ed 53 ff ff       	call   404370 <_traceEvent>
  40ef83:	e9 17 de ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40ef88:	66 0f 6f ad 20 f1 ff 	movdqa -0xee0(%rbp),%xmm5
  40ef8f:	ff 
  40ef90:	48 8b 95 30 f1 ff ff 	mov    -0xed0(%rbp),%rdx
  40ef97:	83 c8 60             	or     $0x60,%eax
  40ef9a:	48 8d 9d c0 f7 ff ff 	lea    -0x840(%rbp),%rbx
  40efa1:	66 0f 6f b5 00 f1 ff 	movdqa -0xf00(%rbp),%xmm6
  40efa8:	ff 
  40efa9:	48 8b 8d 60 f0 ff ff 	mov    -0xfa0(%rbp),%rcx
  40efb0:	48 8d b5 f8 f0 ff ff 	lea    -0xf08(%rbp),%rsi
  40efb7:	48 89 df             	mov    %rbx,%rdi
  40efba:	0f 29 ad a0 f1 ff ff 	movaps %xmm5,-0xe60(%rbp)
  40efc1:	66 89 85 a2 f1 ff ff 	mov    %ax,-0xe5e(%rbp)
  40efc8:	8b 85 10 f1 ff ff    	mov    -0xef0(%rbp),%eax
  40efce:	48 89 95 b0 f1 ff ff 	mov    %rdx,-0xe50(%rbp)
  40efd5:	48 8d 95 a0 f1 ff ff 	lea    -0xe60(%rbp),%rdx
  40efdc:	89 85 30 f2 ff ff    	mov    %eax,-0xdd0(%rbp)
  40efe2:	0f 29 b5 20 f2 ff ff 	movaps %xmm6,-0xde0(%rbp)
  40efe9:	e8 e2 a9 00 00       	call   4199d0 <encode_REGISTER>
  40efee:	48 89 9d b8 f0 ff ff 	mov    %rbx,-0xf48(%rbp)
  40eff5:	e9 49 f7 ff ff       	jmp    40e743 <process_udp.isra.0+0x1b83>
  40effa:	4c 8d bd 14 f2 ff ff 	lea    -0xdec(%rbp),%r15
  40f001:	48 8b 78 48          	mov    0x48(%rax),%rdi
  40f005:	45 31 c0             	xor    %r8d,%r8d
  40f008:	4c 89 f6             	mov    %r14,%rsi
  40f00b:	48 8b 8d e8 f0 ff ff 	mov    -0xf18(%rbp),%rcx
  40f012:	4c 89 fa             	mov    %r15,%rdx
  40f015:	e8 f6 88 ff ff       	call   407910 <find_edge_time_stamp_and_verify>
  40f01a:	85 c0                	test   %eax,%eax
  40f01c:	0f 85 ee f0 ff ff    	jne    40e110 <process_udp.isra.0+0x1550>
  40f022:	48 8d 0d 6f 40 01 00 	lea    0x1406f(%rip),%rcx        # 423098 <_IO_stdin_used+0x2098>
  40f029:	ba 6f 07 00 00       	mov    $0x76f,%edx
  40f02e:	bf 04 00 00 00       	mov    $0x4,%edi
  40f033:	48 8d 35 bb 58 01 00 	lea    0x158bb(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40f03a:	e8 31 53 ff ff       	call   404370 <_traceEvent>
  40f03f:	e9 5b dd ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40f044:	0f 1f 40 00          	nopl   0x0(%rax)
  40f048:	0f b6 77 0a          	movzbl 0xa(%rdi),%esi
  40f04c:	c1 e6 18             	shl    $0x18,%esi
  40f04f:	01 f0                	add    %esi,%eax
  40f051:	0f b6 77 09          	movzbl 0x9(%rdi),%esi
  40f055:	c1 e6 10             	shl    $0x10,%esi
  40f058:	01 f0                	add    %esi,%eax
  40f05a:	0f b6 77 08          	movzbl 0x8(%rdi),%esi
  40f05e:	c1 e6 08             	shl    $0x8,%esi
  40f061:	01 f0                	add    %esi,%eax
  40f063:	0f b6 77 07          	movzbl 0x7(%rdi),%esi
  40f067:	c1 e6 18             	shl    $0x18,%esi
  40f06a:	01 f2                	add    %esi,%edx
  40f06c:	0f b6 77 06          	movzbl 0x6(%rdi),%esi
  40f070:	c1 e6 10             	shl    $0x10,%esi
  40f073:	01 f2                	add    %esi,%edx
  40f075:	0f b6 77 05          	movzbl 0x5(%rdi),%esi
  40f079:	c1 e6 08             	shl    $0x8,%esi
  40f07c:	01 f2                	add    %esi,%edx
  40f07e:	0f b6 77 04          	movzbl 0x4(%rdi),%esi
  40f082:	01 f2                	add    %esi,%edx
  40f084:	0f b6 77 03          	movzbl 0x3(%rdi),%esi
  40f088:	c1 e6 18             	shl    $0x18,%esi
  40f08b:	01 f1                	add    %esi,%ecx
  40f08d:	0f b6 77 02          	movzbl 0x2(%rdi),%esi
  40f091:	c1 e6 10             	shl    $0x10,%esi
  40f094:	01 f1                	add    %esi,%ecx
  40f096:	0f b6 77 01          	movzbl 0x1(%rdi),%esi
  40f09a:	c1 e6 08             	shl    $0x8,%esi
  40f09d:	01 f1                	add    %esi,%ecx
  40f09f:	0f b6 37             	movzbl (%rdi),%esi
  40f0a2:	01 f1                	add    %esi,%ecx
  40f0a4:	8d 34 02             	lea    (%rdx,%rax,1),%esi
  40f0a7:	29 c2                	sub    %eax,%edx
  40f0a9:	29 f1                	sub    %esi,%ecx
  40f0ab:	89 c6                	mov    %eax,%esi
  40f0ad:	c1 ee 0d             	shr    $0xd,%esi
  40f0b0:	31 f1                	xor    %esi,%ecx
  40f0b2:	89 ce                	mov    %ecx,%esi
  40f0b4:	29 ca                	sub    %ecx,%edx
  40f0b6:	29 c8                	sub    %ecx,%eax
  40f0b8:	c1 e6 08             	shl    $0x8,%esi
  40f0bb:	31 f2                	xor    %esi,%edx
  40f0bd:	89 d6                	mov    %edx,%esi
  40f0bf:	29 d0                	sub    %edx,%eax
  40f0c1:	29 d1                	sub    %edx,%ecx
  40f0c3:	c1 ee 0d             	shr    $0xd,%esi
  40f0c6:	31 f0                	xor    %esi,%eax
  40f0c8:	89 ce                	mov    %ecx,%esi
  40f0ca:	89 c1                	mov    %eax,%ecx
  40f0cc:	29 c6                	sub    %eax,%esi
  40f0ce:	29 c2                	sub    %eax,%edx
  40f0d0:	c1 e9 0c             	shr    $0xc,%ecx
  40f0d3:	31 f1                	xor    %esi,%ecx
  40f0d5:	89 d6                	mov    %edx,%esi
  40f0d7:	89 ca                	mov    %ecx,%edx
  40f0d9:	29 ce                	sub    %ecx,%esi
  40f0db:	29 c8                	sub    %ecx,%eax
  40f0dd:	c1 e2 10             	shl    $0x10,%edx
  40f0e0:	31 f2                	xor    %esi,%edx
  40f0e2:	29 d0                	sub    %edx,%eax
  40f0e4:	29 d1                	sub    %edx,%ecx
  40f0e6:	89 c6                	mov    %eax,%esi
  40f0e8:	89 d0                	mov    %edx,%eax
  40f0ea:	c1 e8 05             	shr    $0x5,%eax
  40f0ed:	31 f0                	xor    %esi,%eax
  40f0ef:	89 ce                	mov    %ecx,%esi
  40f0f1:	89 c1                	mov    %eax,%ecx
  40f0f3:	29 c6                	sub    %eax,%esi
  40f0f5:	29 c2                	sub    %eax,%edx
  40f0f7:	c1 e9 03             	shr    $0x3,%ecx
  40f0fa:	31 f1                	xor    %esi,%ecx
  40f0fc:	89 ce                	mov    %ecx,%esi
  40f0fe:	29 ca                	sub    %ecx,%edx
  40f100:	29 c8                	sub    %ecx,%eax
  40f102:	c1 e6 0a             	shl    $0xa,%esi
  40f105:	31 f2                	xor    %esi,%edx
  40f107:	29 d0                	sub    %edx,%eax
  40f109:	c1 ea 0f             	shr    $0xf,%edx
  40f10c:	31 c2                	xor    %eax,%edx
  40f10e:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40f115:	89 d3                	mov    %edx,%ebx
  40f117:	48 8b 50 70          	mov    0x70(%rax),%rdx
  40f11b:	8b 42 08             	mov    0x8(%rdx),%eax
  40f11e:	83 e8 01             	sub    $0x1,%eax
  40f121:	21 d8                	and    %ebx,%eax
  40f123:	48 c1 e0 04          	shl    $0x4,%rax
  40f127:	48 03 02             	add    (%rdx),%rax
  40f12a:	4c 8b 10             	mov    (%rax),%r10
  40f12d:	4d 85 d2             	test   %r10,%r10
  40f130:	0f 84 93 0c 00 00    	je     40fdc9 <process_udp.isra.0+0x3209>
  40f136:	48 8b 42 20          	mov    0x20(%rdx),%rax
  40f13a:	45 89 c9             	mov    %r9d,%r9d
  40f13d:	49 89 c6             	mov    %rax,%r14
  40f140:	49 29 c2             	sub    %rax,%r10
  40f143:	49 f7 de             	neg    %r14
  40f146:	4d 89 d5             	mov    %r10,%r13
  40f149:	eb 18                	jmp    40f163 <process_udp.isra.0+0x25a3>
  40f14b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  40f150:	4d 8b ad 90 00 00 00 	mov    0x90(%r13),%r13
  40f157:	4d 85 ed             	test   %r13,%r13
  40f15a:	0f 84 69 0c 00 00    	je     40fdc9 <process_udp.isra.0+0x3209>
  40f160:	4d 01 f5             	add    %r14,%r13
  40f163:	41 3b 9d a4 00 00 00 	cmp    0xa4(%r13),%ebx
  40f16a:	75 e4                	jne    40f150 <process_udp.isra.0+0x2590>
  40f16c:	45 3b bd a0 00 00 00 	cmp    0xa0(%r13),%r15d
  40f173:	75 db                	jne    40f150 <process_udp.isra.0+0x2590>
  40f175:	49 8b bd 98 00 00 00 	mov    0x98(%r13),%rdi
  40f17c:	4c 89 ca             	mov    %r9,%rdx
  40f17f:	4c 89 e6             	mov    %r12,%rsi
  40f182:	4c 89 8d c8 f0 ff ff 	mov    %r9,-0xf38(%rbp)
  40f189:	e8 e2 34 ff ff       	call   402670 <memcmp@plt>
  40f18e:	4c 8b 8d c8 f0 ff ff 	mov    -0xf38(%rbp),%r9
  40f195:	85 c0                	test   %eax,%eax
  40f197:	75 b7                	jne    40f150 <process_udp.isra.0+0x2590>
  40f199:	41 0f b6 45 16       	movzbl 0x16(%r13),%eax
  40f19e:	4c 89 ad c8 f0 ff ff 	mov    %r13,-0xf38(%rbp)
  40f1a5:	3c 02                	cmp    $0x2,%al
  40f1a7:	0f 84 68 1e 00 00    	je     411015 <process_udp.isra.0+0x4455>
  40f1ad:	84 c0                	test   %al,%al
  40f1af:	0f 84 90 16 00 00    	je     410845 <process_udp.isra.0+0x3c85>
  40f1b5:	45 31 ff             	xor    %r15d,%r15d
  40f1b8:	e9 c1 dd ff ff       	jmp    40cf7e <process_udp.isra.0+0x3be>
  40f1bd:	0f 1f 00             	nopl   (%rax)
  40f1c0:	41 8b 40 10          	mov    0x10(%r8),%eax
  40f1c4:	39 41 10             	cmp    %eax,0x10(%rcx)
  40f1c7:	0f 85 c1 fa ff ff    	jne    40ec8e <process_udp.isra.0+0x20ce>
  40f1cd:	e9 9c fb ff ff       	jmp    40ed6e <process_udp.isra.0+0x21ae>
  40f1d2:	4d 89 f0             	mov    %r14,%r8
  40f1d5:	ba 5a 09 00 00       	mov    $0x95a,%edx
  40f1da:	bf 04 00 00 00       	mov    $0x4,%edi
  40f1df:	31 c0                	xor    %eax,%eax
  40f1e1:	48 8d 0d b8 42 01 00 	lea    0x142b8(%rip),%rcx        # 4234a0 <_IO_stdin_used+0x24a0>
  40f1e8:	48 8d 35 06 57 01 00 	lea    0x15706(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40f1ef:	e8 7c 51 ff ff       	call   404370 <_traceEvent>
  40f1f4:	e9 a6 db ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40f1f9:	48 8b 9d c8 f0 ff ff 	mov    -0xf38(%rbp),%rbx
  40f200:	66 0f ef c0          	pxor   %xmm0,%xmm0
  40f204:	48 c7 85 f8 f0 ff ff 	movq   $0x0,-0xf08(%rbp)
  40f20b:	00 00 00 00 
  40f20f:	c7 85 d0 f7 ff ff 00 	movl   $0x0,-0x830(%rbp)
  40f216:	00 00 00 
  40f219:	0f 29 85 c0 f7 ff ff 	movaps %xmm0,-0x840(%rbp)
  40f220:	0f b6 7b 6c          	movzbl 0x6c(%rbx),%edi
  40f224:	4c 89 95 c0 f0 ff ff 	mov    %r10,-0xf40(%rbp)
  40f22b:	e8 50 56 ff ff       	call   404880 <bitlen2mask>
  40f230:	44 8b 73 68          	mov    0x68(%rbx),%r14d
  40f234:	4c 8b 43 48          	mov    0x48(%rbx),%r8
  40f238:	41 89 c5             	mov    %eax,%r13d
  40f23b:	4c 8b 95 c0 f0 ff ff 	mov    -0xf40(%rbp),%r10
  40f242:	41 21 c6             	and    %eax,%r14d
  40f245:	f7 d0                	not    %eax
  40f247:	4d 85 c0             	test   %r8,%r8
  40f24a:	89 85 44 f0 ff ff    	mov    %eax,-0xfbc(%rbp)
  40f250:	0f 84 f8 02 00 00    	je     40f54e <process_udp.isra.0+0x298e>
  40f256:	4c 89 95 58 f0 ff ff 	mov    %r10,-0xfa8(%rbp)
  40f25d:	4d 8d a0 e8 00 00 00 	lea    0xe8(%r8),%r12
  40f264:	41 bf 01 00 00 00    	mov    $0x1,%r15d
  40f26a:	44 89 ad 48 f0 ff ff 	mov    %r13d,-0xfb8(%rbp)
  40f271:	4d 89 e5             	mov    %r12,%r13
  40f274:	44 89 b5 68 f0 ff ff 	mov    %r14d,-0xf98(%rbp)
  40f27b:	45 89 fe             	mov    %r15d,%r14d
  40f27e:	4d 89 ec             	mov    %r13,%r12
  40f281:	31 c0                	xor    %eax,%eax
  40f283:	45 89 f7             	mov    %r14d,%r15d
  40f286:	31 db                	xor    %ebx,%ebx
  40f288:	4d 89 e6             	mov    %r12,%r14
  40f28b:	45 31 ed             	xor    %r13d,%r13d
  40f28e:	41 89 c4             	mov    %eax,%r12d
  40f291:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  40f298:	41 83 c4 01          	add    $0x1,%r12d
  40f29c:	4c 89 f0             	mov    %r14,%rax
  40f29f:	45 31 d2             	xor    %r10d,%r10d
  40f2a2:	45 85 ff             	test   %r15d,%r15d
  40f2a5:	75 19                	jne    40f2c0 <process_udp.isra.0+0x2700>
  40f2a7:	eb 24                	jmp    40f2cd <process_udp.isra.0+0x270d>
  40f2a9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  40f2b0:	49 8b 90 e8 00 00 00 	mov    0xe8(%r8),%rdx
  40f2b7:	48 03 42 20          	add    0x20(%rdx),%rax
  40f2bb:	45 39 fa             	cmp    %r15d,%r10d
  40f2be:	74 0d                	je     40f2cd <process_udp.isra.0+0x270d>
  40f2c0:	48 8b 40 10          	mov    0x10(%rax),%rax
  40f2c4:	41 83 c2 01          	add    $0x1,%r10d
  40f2c8:	48 85 c0             	test   %rax,%rax
  40f2cb:	75 e3                	jne    40f2b0 <process_udp.isra.0+0x26f0>
  40f2cd:	4c 89 f1             	mov    %r14,%rcx
  40f2d0:	44 89 fa             	mov    %r15d,%edx
  40f2d3:	49 89 c6             	mov    %rax,%r14
  40f2d6:	44 89 e6             	mov    %r12d,%esi
  40f2d9:	45 85 d2             	test   %r10d,%r10d
  40f2dc:	75 5e                	jne    40f33c <process_udp.isra.0+0x277c>
  40f2de:	85 d2                	test   %edx,%edx
  40f2e0:	0f 84 42 03 00 00    	je     40f628 <process_udp.isra.0+0x2a68>
  40f2e6:	4d 85 f6             	test   %r14,%r14
  40f2e9:	0f 84 01 02 00 00    	je     40f4f0 <process_udp.isra.0+0x2930>
  40f2ef:	49 8b 46 10          	mov    0x10(%r14),%rax
  40f2f3:	48 85 c0             	test   %rax,%rax
  40f2f6:	74 0b                	je     40f303 <process_udp.isra.0+0x2743>
  40f2f8:	49 8b b8 e8 00 00 00 	mov    0xe8(%r8),%rdi
  40f2ff:	48 03 47 20          	add    0x20(%rdi),%rax
  40f303:	83 ea 01             	sub    $0x1,%edx
  40f306:	48 85 db             	test   %rbx,%rbx
  40f309:	0f 84 f9 00 00 00    	je     40f408 <process_udp.isra.0+0x2848>
  40f30f:	49 8b b8 e8 00 00 00 	mov    0xe8(%r8),%rdi
  40f316:	4d 89 f1             	mov    %r14,%r9
  40f319:	49 89 c6             	mov    %rax,%r14
  40f31c:	48 8b 7f 20          	mov    0x20(%rdi),%rdi
  40f320:	4c 89 c8             	mov    %r9,%rax
  40f323:	48 29 f8             	sub    %rdi,%rax
  40f326:	48 89 43 10          	mov    %rax,0x10(%rbx)
  40f32a:	48 89 d8             	mov    %rbx,%rax
  40f32d:	4c 89 cb             	mov    %r9,%rbx
  40f330:	48 29 f8             	sub    %rdi,%rax
  40f333:	48 89 43 08          	mov    %rax,0x8(%rbx)
  40f337:	45 85 d2             	test   %r10d,%r10d
  40f33a:	74 a2                	je     40f2de <process_udp.isra.0+0x271e>
  40f33c:	85 d2                	test   %edx,%edx
  40f33e:	0f 84 dc 00 00 00    	je     40f420 <process_udp.isra.0+0x2860>
  40f344:	4d 85 f6             	test   %r14,%r14
  40f347:	0f 84 d3 00 00 00    	je     40f420 <process_udp.isra.0+0x2860>
  40f34d:	49 8b 80 e8 00 00 00 	mov    0xe8(%r8),%rax
  40f354:	4d 89 f0             	mov    %r14,%r8
  40f357:	89 95 a0 f0 ff ff    	mov    %edx,-0xf60(%rbp)
  40f35d:	89 b5 a8 f0 ff ff    	mov    %esi,-0xf58(%rbp)
  40f363:	48 8b 78 20          	mov    0x20(%rax),%rdi
  40f367:	48 89 c8             	mov    %rcx,%rax
  40f36a:	44 89 95 b0 f0 ff ff 	mov    %r10d,-0xf50(%rbp)
  40f371:	48 89 8d b8 f0 ff ff 	mov    %rcx,-0xf48(%rbp)
  40f378:	48 29 f8             	sub    %rdi,%rax
  40f37b:	49 29 f8             	sub    %rdi,%r8
  40f37e:	0f b6 78 0c          	movzbl 0xc(%rax),%edi
  40f382:	44 8b 60 08          	mov    0x8(%rax),%r12d
  40f386:	4c 89 85 c0 f0 ff ff 	mov    %r8,-0xf40(%rbp)
  40f38d:	e8 ee 54 ff ff       	call   404880 <bitlen2mask>
  40f392:	4c 8b 85 c0 f0 ff ff 	mov    -0xf40(%rbp),%r8
  40f399:	f7 d0                	not    %eax
  40f39b:	41 21 c4             	and    %eax,%r12d
  40f39e:	41 0f b6 78 0c       	movzbl 0xc(%r8),%edi
  40f3a3:	41 8b 40 08          	mov    0x8(%r8),%eax
  40f3a7:	89 85 c0 f0 ff ff    	mov    %eax,-0xf40(%rbp)
  40f3ad:	e8 ce 54 ff ff       	call   404880 <bitlen2mask>
  40f3b2:	8b b5 c0 f0 ff ff    	mov    -0xf40(%rbp),%esi
  40f3b8:	48 8b 8d b8 f0 ff ff 	mov    -0xf48(%rbp),%rcx
  40f3bf:	f7 d0                	not    %eax
  40f3c1:	44 8b 95 b0 f0 ff ff 	mov    -0xf50(%rbp),%r10d
  40f3c8:	8b 95 a0 f0 ff ff    	mov    -0xf60(%rbp),%edx
  40f3ce:	21 f0                	and    %esi,%eax
  40f3d0:	8b b5 a8 f0 ff ff    	mov    -0xf58(%rbp),%esi
  40f3d6:	41 39 c4             	cmp    %eax,%r12d
  40f3d9:	0f 8e b1 00 00 00    	jle    40f490 <process_udp.isra.0+0x28d0>
  40f3df:	48 8b bd c8 f0 ff ff 	mov    -0xf38(%rbp),%rdi
  40f3e6:	49 8b 46 10          	mov    0x10(%r14),%rax
  40f3ea:	4c 8b 47 48          	mov    0x48(%rdi),%r8
  40f3ee:	48 85 c0             	test   %rax,%rax
  40f3f1:	0f 85 01 ff ff ff    	jne    40f2f8 <process_udp.isra.0+0x2738>
  40f3f7:	83 ea 01             	sub    $0x1,%edx
  40f3fa:	48 85 db             	test   %rbx,%rbx
  40f3fd:	0f 85 0c ff ff ff    	jne    40f30f <process_udp.isra.0+0x274f>
  40f403:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  40f408:	4d 89 f5             	mov    %r14,%r13
  40f40b:	4c 89 f3             	mov    %r14,%rbx
  40f40e:	49 89 c6             	mov    %rax,%r14
  40f411:	31 c0                	xor    %eax,%eax
  40f413:	e9 1b ff ff ff       	jmp    40f333 <process_udp.isra.0+0x2773>
  40f418:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  40f41f:	00 
  40f420:	41 83 ea 01          	sub    $0x1,%r10d
  40f424:	48 85 c9             	test   %rcx,%rcx
  40f427:	74 2f                	je     40f458 <process_udp.isra.0+0x2898>
  40f429:	48 8b 41 10          	mov    0x10(%rcx),%rax
  40f42d:	48 85 c0             	test   %rax,%rax
  40f430:	74 3e                	je     40f470 <process_udp.isra.0+0x28b0>
  40f432:	49 8b b8 e8 00 00 00 	mov    0xe8(%r8),%rdi
  40f439:	48 8b 7f 20          	mov    0x20(%rdi),%rdi
  40f43d:	4c 8d 1c 38          	lea    (%rax,%rdi,1),%r11
  40f441:	48 85 db             	test   %rbx,%rbx
  40f444:	74 7a                	je     40f4c0 <process_udp.isra.0+0x2900>
  40f446:	49 89 c9             	mov    %rcx,%r9
  40f449:	4c 89 d9             	mov    %r11,%rcx
  40f44c:	e9 cf fe ff ff       	jmp    40f320 <process_udp.isra.0+0x2760>
  40f451:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  40f458:	48 85 db             	test   %rbx,%rbx
  40f45b:	0f 84 7f 00 00 00    	je     40f4e0 <process_udp.isra.0+0x2920>
  40f461:	48 c7 43 10 00 00 00 	movq   $0x0,0x10(%rbx)
  40f468:	00 
  40f469:	31 db                	xor    %ebx,%ebx
  40f46b:	e9 69 fe ff ff       	jmp    40f2d9 <process_udp.isra.0+0x2719>
  40f470:	48 85 db             	test   %rbx,%rbx
  40f473:	0f 84 c7 01 00 00    	je     40f640 <process_udp.isra.0+0x2a80>
  40f479:	49 8b 80 e8 00 00 00 	mov    0xe8(%r8),%rax
  40f480:	49 89 c9             	mov    %rcx,%r9
  40f483:	31 c9                	xor    %ecx,%ecx
  40f485:	48 8b 78 20          	mov    0x20(%rax),%rdi
  40f489:	e9 92 fe ff ff       	jmp    40f320 <process_udp.isra.0+0x2760>
  40f48e:	66 90                	xchg   %ax,%ax
  40f490:	41 83 ea 01          	sub    $0x1,%r10d
  40f494:	48 85 c9             	test   %rcx,%rcx
  40f497:	0f 84 c3 01 00 00    	je     40f660 <process_udp.isra.0+0x2aa0>
  40f49d:	48 8b 41 10          	mov    0x10(%rcx),%rax
  40f4a1:	48 85 c0             	test   %rax,%rax
  40f4a4:	0f 84 d6 01 00 00    	je     40f680 <process_udp.isra.0+0x2ac0>
  40f4aa:	48 8b bd c8 f0 ff ff 	mov    -0xf38(%rbp),%rdi
  40f4b1:	4c 8b 47 48          	mov    0x48(%rdi),%r8
  40f4b5:	e9 78 ff ff ff       	jmp    40f432 <process_udp.isra.0+0x2872>
  40f4ba:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
  40f4c0:	4c 89 f0             	mov    %r14,%rax
  40f4c3:	49 89 ce             	mov    %rcx,%r14
  40f4c6:	4c 89 d9             	mov    %r11,%rcx
  40f4c9:	4d 89 f5             	mov    %r14,%r13
  40f4cc:	4c 89 f3             	mov    %r14,%rbx
  40f4cf:	49 89 c6             	mov    %rax,%r14
  40f4d2:	31 c0                	xor    %eax,%eax
  40f4d4:	e9 5a fe ff ff       	jmp    40f333 <process_udp.isra.0+0x2773>
  40f4d9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  40f4e0:	45 31 ed             	xor    %r13d,%r13d
  40f4e3:	e9 f1 fd ff ff       	jmp    40f2d9 <process_udp.isra.0+0x2719>
  40f4e8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  40f4ef:	00 
  40f4f0:	45 89 fe             	mov    %r15d,%r14d
  40f4f3:	89 f0                	mov    %esi,%eax
  40f4f5:	48 85 db             	test   %rbx,%rbx
  40f4f8:	74 08                	je     40f502 <process_udp.isra.0+0x2942>
  40f4fa:	48 c7 43 10 00 00 00 	movq   $0x0,0x10(%rbx)
  40f501:	00 
  40f502:	83 f8 01             	cmp    $0x1,%eax
  40f505:	0f 86 c0 01 00 00    	jbe    40f6cb <process_udp.isra.0+0x2b0b>
  40f50b:	45 01 f6             	add    %r14d,%r14d
  40f50e:	4d 85 ed             	test   %r13,%r13
  40f511:	0f 85 67 fd ff ff    	jne    40f27e <process_udp.isra.0+0x26be>
  40f517:	4d 89 ec             	mov    %r13,%r12
  40f51a:	4c 8b 95 58 f0 ff ff 	mov    -0xfa8(%rbp),%r10
  40f521:	44 8b ad 48 f0 ff ff 	mov    -0xfb8(%rbp),%r13d
  40f528:	31 db                	xor    %ebx,%ebx
  40f52a:	44 8b b5 68 f0 ff ff 	mov    -0xf98(%rbp),%r14d
  40f531:	49 8b 80 e8 00 00 00 	mov    0xe8(%r8),%rax
  40f538:	4c 89 e6             	mov    %r12,%rsi
  40f53b:	48 89 58 18          	mov    %rbx,0x18(%rax)
  40f53f:	48 2b 70 20          	sub    0x20(%rax),%rsi
  40f543:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40f54a:	48 89 70 48          	mov    %rsi,0x48(%rax)
  40f54e:	be 10 00 00 00       	mov    $0x10,%esi
  40f553:	48 8d bd 38 f2 ff ff 	lea    -0xdc8(%rbp),%rdi
  40f55a:	4c 89 95 c0 f0 ff ff 	mov    %r10,-0xf40(%rbp)
  40f561:	e8 2a 75 ff ff       	call   406a90 <pearson_hash_32>
  40f566:	8b b5 44 f0 ff ff    	mov    -0xfbc(%rbp),%esi
  40f56c:	ba 01 00 00 00       	mov    $0x1,%edx
  40f571:	4c 8b 95 c0 f0 ff ff 	mov    -0xf40(%rbp),%r10
  40f578:	21 f0                	and    %esi,%eax
  40f57a:	0f 44 c2             	cmove  %edx,%eax
  40f57d:	31 d2                	xor    %edx,%edx
  40f57f:	39 c6                	cmp    %eax,%esi
  40f581:	48 8b b5 c8 f0 ff ff 	mov    -0xf38(%rbp),%rsi
  40f588:	0f 94 c2             	sete   %dl
  40f58b:	29 d0                	sub    %edx,%eax
  40f58d:	0f b6 56 6c          	movzbl 0x6c(%rsi),%edx
  40f591:	44 09 f0             	or     %r14d,%eax
  40f594:	41 39 c6             	cmp    %eax,%r14d
  40f597:	88 95 fc f0 ff ff    	mov    %dl,-0xf04(%rbp)
  40f59d:	0f 83 bc 01 00 00    	jae    40f75f <process_udp.isra.0+0x2b9f>
  40f5a3:	48 8b b5 c8 f0 ff ff 	mov    -0xf38(%rbp),%rsi
  40f5aa:	48 8b 76 48          	mov    0x48(%rsi),%rsi
  40f5ae:	48 85 f6             	test   %rsi,%rsi
  40f5b1:	0f 85 7c 0b 00 00    	jne    410133 <process_udp.isra.0+0x3573>
  40f5b7:	89 85 f8 f0 ff ff    	mov    %eax,-0xf08(%rbp)
  40f5bd:	48 8d 85 c0 f7 ff ff 	lea    -0x840(%rbp),%rax
  40f5c4:	48 8d b5 f8 f0 ff ff 	lea    -0xf08(%rbp),%rsi
  40f5cb:	4c 89 95 c0 f0 ff ff 	mov    %r10,-0xf40(%rbp)
  40f5d2:	48 89 c7             	mov    %rax,%rdi
  40f5d5:	e8 b6 60 ff ff       	call   405690 <ip_subnet_to_str>
  40f5da:	ba eb 04 00 00       	mov    $0x4eb,%edx
  40f5df:	bf 03 00 00 00       	mov    $0x3,%edi
  40f5e4:	48 8d 0d 8d 3b 01 00 	lea    0x13b8d(%rip),%rcx        # 423178 <_IO_stdin_used+0x2178>
  40f5eb:	49 89 c0             	mov    %rax,%r8
  40f5ee:	48 8d 35 00 53 01 00 	lea    0x15300(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40f5f5:	31 c0                	xor    %eax,%eax
  40f5f7:	e8 74 4d ff ff       	call   404370 <_traceEvent>
  40f5fc:	4c 8b 95 c0 f0 ff ff 	mov    -0xf40(%rbp),%r10
  40f603:	8b 85 f8 f0 ff ff    	mov    -0xf08(%rbp),%eax
  40f609:	89 85 ac f1 ff ff    	mov    %eax,-0xe54(%rbp)
  40f60f:	0f b6 85 fc f0 ff ff 	movzbl -0xf04(%rbp),%eax
  40f616:	88 85 b0 f1 ff ff    	mov    %al,-0xe50(%rbp)
  40f61c:	e9 8c f5 ff ff       	jmp    40ebad <process_udp.isra.0+0x1fed>
  40f621:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
  40f628:	41 89 f4             	mov    %esi,%r12d
  40f62b:	4d 85 f6             	test   %r14,%r14
  40f62e:	0f 85 64 fc ff ff    	jne    40f298 <process_udp.isra.0+0x26d8>
  40f634:	45 89 fe             	mov    %r15d,%r14d
  40f637:	89 f0                	mov    %esi,%eax
  40f639:	e9 b7 fe ff ff       	jmp    40f4f5 <process_udp.isra.0+0x2935>
  40f63e:	66 90                	xchg   %ax,%ax
  40f640:	4c 89 f0             	mov    %r14,%rax
  40f643:	49 89 ce             	mov    %rcx,%r14
  40f646:	31 c9                	xor    %ecx,%ecx
  40f648:	4d 89 f5             	mov    %r14,%r13
  40f64b:	4c 89 f3             	mov    %r14,%rbx
  40f64e:	49 89 c6             	mov    %rax,%r14
  40f651:	31 c0                	xor    %eax,%eax
  40f653:	e9 db fc ff ff       	jmp    40f333 <process_udp.isra.0+0x2773>
  40f658:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  40f65f:	00 
  40f660:	48 85 db             	test   %rbx,%rbx
  40f663:	74 30                	je     40f695 <process_udp.isra.0+0x2ad5>
  40f665:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40f66c:	48 c7 43 10 00 00 00 	movq   $0x0,0x10(%rbx)
  40f673:	00 
  40f674:	31 db                	xor    %ebx,%ebx
  40f676:	4c 8b 40 48          	mov    0x48(%rax),%r8
  40f67a:	e9 5a fc ff ff       	jmp    40f2d9 <process_udp.isra.0+0x2719>
  40f67f:	90                   	nop
  40f680:	48 85 db             	test   %rbx,%rbx
  40f683:	74 23                	je     40f6a8 <process_udp.isra.0+0x2ae8>
  40f685:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40f68c:	4c 8b 40 48          	mov    0x48(%rax),%r8
  40f690:	e9 e4 fd ff ff       	jmp    40f479 <process_udp.isra.0+0x28b9>
  40f695:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40f69c:	45 31 ed             	xor    %r13d,%r13d
  40f69f:	4c 8b 40 48          	mov    0x48(%rax),%r8
  40f6a3:	e9 31 fc ff ff       	jmp    40f2d9 <process_udp.isra.0+0x2719>
  40f6a8:	48 8b 9d c8 f0 ff ff 	mov    -0xf38(%rbp),%rbx
  40f6af:	4c 89 f0             	mov    %r14,%rax
  40f6b2:	49 89 ce             	mov    %rcx,%r14
  40f6b5:	31 c9                	xor    %ecx,%ecx
  40f6b7:	4d 89 f5             	mov    %r14,%r13
  40f6ba:	4c 8b 43 48          	mov    0x48(%rbx),%r8
  40f6be:	4c 89 f3             	mov    %r14,%rbx
  40f6c1:	49 89 c6             	mov    %rax,%r14
  40f6c4:	31 c0                	xor    %eax,%eax
  40f6c6:	e9 68 fc ff ff       	jmp    40f333 <process_udp.isra.0+0x2773>
  40f6cb:	4d 89 ec             	mov    %r13,%r12
  40f6ce:	4c 8b 95 58 f0 ff ff 	mov    -0xfa8(%rbp),%r10
  40f6d5:	44 8b ad 48 f0 ff ff 	mov    -0xfb8(%rbp),%r13d
  40f6dc:	44 8b b5 68 f0 ff ff 	mov    -0xf98(%rbp),%r14d
  40f6e3:	e9 49 fe ff ff       	jmp    40f531 <process_udp.isra.0+0x2971>
  40f6e8:	48 83 ec 08          	sub    $0x8,%rsp
  40f6ec:	ff 75 10             	push   0x10(%rbp)
  40f6ef:	4c 8b 8d c0 f0 ff ff 	mov    -0xf40(%rbp),%r9
  40f6f6:	4c 8b 85 b8 f0 ff ff 	mov    -0xf48(%rbp),%r8
  40f6fd:	48 8b 95 60 f0 ff ff 	mov    -0xfa0(%rbp),%rdx
  40f704:	48 8b b5 c8 f0 ff ff 	mov    -0xf38(%rbp),%rsi
  40f70b:	48 8b bd 98 f0 ff ff 	mov    -0xf68(%rbp),%rdi
  40f712:	e8 b9 9c ff ff       	call   4093d0 <try_broadcast.isra.0>
  40f717:	5b                   	pop    %rbx
  40f718:	41 5c                	pop    %r12
  40f71a:	e9 80 d6 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40f71f:	48 8d 85 a0 f1 ff ff 	lea    -0xe60(%rbp),%rax
  40f726:	4c 8b 85 90 f0 ff ff 	mov    -0xf70(%rbp),%r8
  40f72d:	4c 89 e1             	mov    %r12,%rcx
  40f730:	48 8b 95 b8 f0 ff ff 	mov    -0xf48(%rbp),%rdx
  40f737:	48 8b b5 88 f0 ff ff 	mov    -0xf78(%rbp),%rsi
  40f73e:	48 89 c7             	mov    %rax,%rdi
  40f741:	48 89 85 50 f0 ff ff 	mov    %rax,-0xfb0(%rbp)
  40f748:	4c 8d bd a2 f1 ff ff 	lea    -0xe5e(%rbp),%r15
  40f74f:	e8 bc ba 00 00       	call   41b210 <decode_QUERY_PEER>
  40f754:	e9 2d da ff ff       	jmp    40d186 <process_udp.isra.0+0x5c6>
  40f759:	89 95 f8 f0 ff ff    	mov    %edx,-0xf08(%rbp)
  40f75f:	44 89 f6             	mov    %r14d,%esi
  40f762:	8d 50 01             	lea    0x1(%rax),%edx
  40f765:	44 29 ee             	sub    %r13d,%esi
  40f768:	83 ee 01             	sub    $0x1,%esi
  40f76b:	39 f2                	cmp    %esi,%edx
  40f76d:	0f 83 0b 12 00 00    	jae    41097e <process_udp.isra.0+0x3dbe>
  40f773:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  40f77a:	48 8b 78 48          	mov    0x48(%rax),%rdi
  40f77e:	48 85 ff             	test   %rdi,%rdi
  40f781:	0f 85 a7 0d 00 00    	jne    41052e <process_udp.isra.0+0x396e>
  40f787:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
  40f78e:	00 00 
  40f790:	89 95 f8 f0 ff ff    	mov    %edx,-0xf08(%rbp)
  40f796:	e9 22 fe ff ff       	jmp    40f5bd <process_udp.isra.0+0x29fd>
  40f79b:	0f b7 40 04          	movzwl 0x4(%rax),%eax
  40f79f:	66 39 85 18 f2 ff ff 	cmp    %ax,-0xde8(%rbp)
  40f7a6:	0f 85 7b f3 ff ff    	jne    40eb27 <process_udp.isra.0+0x1f67>
  40f7ac:	48 8d 0d 9d 39 01 00 	lea    0x1399d(%rip),%rcx        # 423150 <_IO_stdin_used+0x2150>
  40f7b3:	ba b8 07 00 00       	mov    $0x7b8,%edx
  40f7b8:	48 8d 35 36 51 01 00 	lea    0x15136(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40f7bf:	31 c0                	xor    %eax,%eax
  40f7c1:	bf 04 00 00 00       	mov    $0x4,%edi
  40f7c6:	e8 a5 4b ff ff       	call   404370 <_traceEvent>
  40f7cb:	e9 cf d5 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40f7d0:	48 8b 78 48          	mov    0x48(%rax),%rdi
  40f7d4:	45 31 c0             	xor    %r8d,%r8d
  40f7d7:	48 89 da             	mov    %rbx,%rdx
  40f7da:	4c 89 f6             	mov    %r14,%rsi
  40f7dd:	48 8b 8d e8 f0 ff ff 	mov    -0xf18(%rbp),%rcx
  40f7e4:	e8 27 81 ff ff       	call   407910 <find_edge_time_stamp_and_verify>
  40f7e9:	85 c0                	test   %eax,%eax
  40f7eb:	0f 85 d0 dc ff ff    	jne    40d4c1 <process_udp.isra.0+0x901>
  40f7f1:	48 8d 0d e0 3d 01 00 	lea    0x13de0(%rip),%rcx        # 4235d8 <_IO_stdin_used+0x25d8>
  40f7f8:	ba e9 09 00 00       	mov    $0x9e9,%edx
  40f7fd:	bf 04 00 00 00       	mov    $0x4,%edi
  40f802:	48 8d 35 ec 50 01 00 	lea    0x150ec(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40f809:	e8 62 4b ff ff       	call   404370 <_traceEvent>
  40f80e:	e9 8c d5 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40f813:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  40f818:	48 8b 78 48          	mov    0x48(%rax),%rdi
  40f81c:	45 31 c0             	xor    %r8d,%r8d
  40f81f:	4c 89 fa             	mov    %r15,%rdx
  40f822:	4c 89 f6             	mov    %r14,%rsi
  40f825:	48 8b 8d e8 f0 ff ff 	mov    -0xf18(%rbp),%rcx
  40f82c:	e8 df 80 ff ff       	call   407910 <find_edge_time_stamp_and_verify>
  40f831:	85 c0                	test   %eax,%eax
  40f833:	0f 85 46 df ff ff    	jne    40d77f <process_udp.isra.0+0xbbf>
  40f839:	48 8d 0d f0 3a 01 00 	lea    0x13af0(%rip),%rcx        # 423330 <_IO_stdin_used+0x2330>
  40f840:	ba c6 08 00 00       	mov    $0x8c6,%edx
  40f845:	bf 04 00 00 00       	mov    $0x4,%edi
  40f84a:	48 8d 35 a4 50 01 00 	lea    0x150a4(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40f851:	e8 1a 4b ff ff       	call   404370 <_traceEvent>
  40f856:	e9 44 d5 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40f85b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  40f860:	4c 89 ff             	mov    %r15,%rdi
  40f863:	4c 89 95 c0 f0 ff ff 	mov    %r10,-0xf40(%rbp)
  40f86a:	e8 d1 53 ff ff       	call   404c40 <is_null_mac>
  40f86f:	48 83 ec 08          	sub    $0x8,%rsp
  40f873:	ff 75 10             	push   0x10(%rbp)
  40f876:	44 8b 8d 80 f0 ff ff 	mov    -0xf80(%rbp),%r9d
  40f87d:	84 c0                	test   %al,%al
  40f87f:	4c 8b 85 48 f0 ff ff 	mov    -0xfb8(%rbp),%r8
  40f886:	0f 95 c0             	setne  %al
  40f889:	48 8b 8d c8 f0 ff ff 	mov    -0xf38(%rbp),%rcx
  40f890:	0f b6 c0             	movzbl %al,%eax
  40f893:	50                   	push   %rax
  40f894:	48 8d 85 ca f1 ff ff 	lea    -0xe36(%rbp),%rax
  40f89b:	50                   	push   %rax
  40f89c:	e9 97 f5 ff ff       	jmp    40ee38 <process_udp.isra.0+0x2278>
  40f8a1:	48 8b 78 48          	mov    0x48(%rax),%rdi
  40f8a5:	45 31 c0             	xor    %r8d,%r8d
  40f8a8:	4c 89 e2             	mov    %r12,%rdx
  40f8ab:	4c 89 f6             	mov    %r14,%rsi
  40f8ae:	48 8b 8d e8 f0 ff ff 	mov    -0xf18(%rbp),%rcx
  40f8b5:	e8 56 80 ff ff       	call   407910 <find_edge_time_stamp_and_verify>
  40f8ba:	85 c0                	test   %eax,%eax
  40f8bc:	0f 85 56 e1 ff ff    	jne    40da18 <process_udp.isra.0+0xe58>
  40f8c2:	48 8d 0d af 39 01 00 	lea    0x139af(%rip),%rcx        # 423278 <_IO_stdin_used+0x2278>
  40f8c9:	ba 92 08 00 00       	mov    $0x892,%edx
  40f8ce:	bf 04 00 00 00       	mov    $0x4,%edi
  40f8d3:	48 8d 35 1b 50 01 00 	lea    0x1501b(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40f8da:	e8 91 4a ff ff       	call   404370 <_traceEvent>
  40f8df:	e9 bb d4 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40f8e4:	0f 1f 40 00          	nopl   0x0(%rax)
  40f8e8:	48 8b 78 48          	mov    0x48(%rax),%rdi
  40f8ec:	48 8b 8d e8 f0 ff ff 	mov    -0xf18(%rbp),%rcx
  40f8f3:	41 b8 01 00 00 00    	mov    $0x1,%r8d
  40f8f9:	4c 89 f6             	mov    %r14,%rsi
  40f8fc:	48 8b 95 60 f0 ff ff 	mov    -0xfa0(%rbp),%rdx
  40f903:	e8 08 80 ff ff       	call   407910 <find_edge_time_stamp_and_verify>
  40f908:	85 c0                	test   %eax,%eax
  40f90a:	0f 85 a3 eb ff ff    	jne    40e4b3 <process_udp.isra.0+0x18f3>
  40f910:	48 8d 0d 99 36 01 00 	lea    0x13699(%rip),%rcx        # 422fb0 <_IO_stdin_used+0x1fb0>
  40f917:	ba cb 06 00 00       	mov    $0x6cb,%edx
  40f91c:	bf 04 00 00 00       	mov    $0x4,%edi
  40f921:	48 8d 35 cd 4f 01 00 	lea    0x14fcd(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40f928:	e8 43 4a ff ff       	call   404370 <_traceEvent>
  40f92d:	e9 6d d4 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40f932:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
  40f938:	48 8b 78 48          	mov    0x48(%rax),%rdi
  40f93c:	45 31 c0             	xor    %r8d,%r8d
  40f93f:	4c 89 fa             	mov    %r15,%rdx
  40f942:	4c 89 f6             	mov    %r14,%rsi
  40f945:	48 8b 8d e8 f0 ff ff 	mov    -0xf18(%rbp),%rcx
  40f94c:	e8 bf 7f ff ff       	call   407910 <find_edge_time_stamp_and_verify>
  40f951:	85 c0                	test   %eax,%eax
  40f953:	0f 85 ea e3 ff ff    	jne    40dd43 <process_udp.isra.0+0x1183>
  40f959:	48 8d 0d d8 3a 01 00 	lea    0x13ad8(%rip),%rcx        # 423438 <_IO_stdin_used+0x2438>
  40f960:	ba 16 09 00 00       	mov    $0x916,%edx
  40f965:	bf 04 00 00 00       	mov    $0x4,%edi
  40f96a:	48 8d 35 84 4f 01 00 	lea    0x14f84(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40f971:	e8 fa 49 ff ff       	call   404370 <_traceEvent>
  40f976:	e9 24 d4 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40f97b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  40f980:	48 8d 0d a9 36 01 00 	lea    0x136a9(%rip),%rcx        # 423030 <_IO_stdin_used+0x2030>
  40f987:	ba 46 07 00 00       	mov    $0x746,%edx
  40f98c:	31 ff                	xor    %edi,%edi
  40f98e:	31 c0                	xor    %eax,%eax
  40f990:	48 8d 35 5e 4f 01 00 	lea    0x14f5e(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40f997:	e8 d4 49 ff ff       	call   404370 <_traceEvent>
  40f99c:	e9 fe d3 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40f9a1:	48 8b 78 48          	mov    0x48(%rax),%rdi
  40f9a5:	45 31 c0             	xor    %r8d,%r8d
  40f9a8:	4c 89 f6             	mov    %r14,%rsi
  40f9ab:	48 8b 8d e8 f0 ff ff 	mov    -0xf18(%rbp),%rcx
  40f9b2:	48 8d 95 14 f2 ff ff 	lea    -0xdec(%rbp),%rdx
  40f9b9:	e8 52 7f ff ff       	call   407910 <find_edge_time_stamp_and_verify>
  40f9be:	85 c0                	test   %eax,%eax
  40f9c0:	0f 85 dc ec ff ff    	jne    40e6a2 <process_udp.isra.0+0x1ae2>
  40f9c6:	48 8d 0d 33 36 01 00 	lea    0x13633(%rip),%rcx        # 423000 <_IO_stdin_used+0x2000>
  40f9cd:	ba 1e 07 00 00       	mov    $0x71e,%edx
  40f9d2:	bf 04 00 00 00       	mov    $0x4,%edi
  40f9d7:	48 8d 35 17 4f 01 00 	lea    0x14f17(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40f9de:	e8 8d 49 ff ff       	call   404370 <_traceEvent>
  40f9e3:	e9 b7 d3 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40f9e8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  40f9ef:	00 
  40f9f0:	4c 89 95 c0 f0 ff ff 	mov    %r10,-0xf40(%rbp)
  40f9f7:	e8 04 73 ff ff       	call   406d00 <n2n_rand_sqr>
  40f9fc:	4c 8b 95 c0 f0 ff ff 	mov    -0xf40(%rbp),%r10
  40fa03:	41 89 c1             	mov    %eax,%r9d
  40fa06:	49 8b 86 c0 00 00 00 	mov    0xc0(%r14),%rax
  40fa0d:	48 8b 58 48          	mov    0x48(%rax),%rbx
  40fa11:	48 85 db             	test   %rbx,%rbx
  40fa14:	0f 85 13 f2 ff ff    	jne    40ec2d <process_udp.isra.0+0x206d>
  40fa1a:	45 31 db             	xor    %r11d,%r11d
  40fa1d:	e9 7c f3 ff ff       	jmp    40ed9e <process_udp.isra.0+0x21de>
  40fa22:	48 8b 9d c8 f0 ff ff 	mov    -0xf38(%rbp),%rbx
  40fa29:	4c 8b 45 10          	mov    0x10(%rbp),%r8
  40fa2d:	4c 89 fe             	mov    %r15,%rsi
  40fa30:	8b 8d 6c f0 ff ff    	mov    -0xf94(%rbp),%ecx
  40fa36:	48 8b 95 78 f0 ff ff 	mov    -0xf88(%rbp),%rdx
  40fa3d:	48 89 df             	mov    %rbx,%rdi
  40fa40:	e8 bb ae ff ff       	call   40a900 <update_node_supernode_association>
  40fa45:	4c 8b 43 48          	mov    0x48(%rbx),%r8
  40fa49:	4c 89 c6             	mov    %r8,%rsi
  40fa4c:	4d 85 c0             	test   %r8,%r8
  40fa4f:	0f 84 4a d3 ff ff    	je     40cd9f <process_udp.isra.0+0x1df>
  40fa55:	0f b6 85 19 f2 ff ff 	movzbl -0xde7(%rbp),%eax
  40fa5c:	0f b6 95 18 f2 ff ff 	movzbl -0xde8(%rbp),%edx
  40fa63:	0f b6 8d 14 f2 ff ff 	movzbl -0xdec(%rbp),%ecx
  40fa6a:	c1 e0 08             	shl    $0x8,%eax
  40fa6d:	8d 94 10 b9 79 37 9e 	lea    -0x61c88647(%rax,%rdx,1),%edx
  40fa74:	0f b6 85 17 f2 ff ff 	movzbl -0xde9(%rbp),%eax
  40fa7b:	c1 e0 18             	shl    $0x18,%eax
  40fa7e:	8d 84 08 c4 ba 49 9f 	lea    -0x60b6453c(%rax,%rcx,1),%eax
  40fa85:	0f b6 8d 16 f2 ff ff 	movzbl -0xdea(%rbp),%ecx
  40fa8c:	c1 e1 10             	shl    $0x10,%ecx
  40fa8f:	01 c8                	add    %ecx,%eax
  40fa91:	0f b6 8d 15 f2 ff ff 	movzbl -0xdeb(%rbp),%ecx
  40fa98:	c1 e1 08             	shl    $0x8,%ecx
  40fa9b:	01 c8                	add    %ecx,%eax
  40fa9d:	29 d0                	sub    %edx,%eax
  40fa9f:	81 c2 0b 41 12 01    	add    $0x112410b,%edx
  40faa5:	35 6d f7 07 00       	xor    $0x7f76d,%eax
  40faaa:	89 d1                	mov    %edx,%ecx
  40faac:	89 c2                	mov    %eax,%edx
  40faae:	29 c1                	sub    %eax,%ecx
  40fab0:	c1 e2 08             	shl    $0x8,%edx
  40fab3:	31 ca                	xor    %ecx,%edx
  40fab5:	b9 f5 be ed fe       	mov    $0xfeedbef5,%ecx
  40faba:	29 c1                	sub    %eax,%ecx
  40fabc:	89 d7                	mov    %edx,%edi
  40fabe:	29 d0                	sub    %edx,%eax
  40fac0:	29 d1                	sub    %edx,%ecx
  40fac2:	c1 ef 0d             	shr    $0xd,%edi
  40fac5:	31 cf                	xor    %ecx,%edi
  40fac7:	89 c1                	mov    %eax,%ecx
  40fac9:	89 f8                	mov    %edi,%eax
  40facb:	29 f9                	sub    %edi,%ecx
  40facd:	29 fa                	sub    %edi,%edx
  40facf:	c1 e8 0c             	shr    $0xc,%eax
  40fad2:	31 c1                	xor    %eax,%ecx
  40fad4:	89 c8                	mov    %ecx,%eax
  40fad6:	29 ca                	sub    %ecx,%edx
  40fad8:	c1 e0 10             	shl    $0x10,%eax
  40fadb:	31 c2                	xor    %eax,%edx
  40fadd:	89 f8                	mov    %edi,%eax
  40fadf:	29 c8                	sub    %ecx,%eax
  40fae1:	89 d7                	mov    %edx,%edi
  40fae3:	29 d1                	sub    %edx,%ecx
  40fae5:	c1 ef 05             	shr    $0x5,%edi
  40fae8:	29 d0                	sub    %edx,%eax
  40faea:	31 f8                	xor    %edi,%eax
  40faec:	89 c7                	mov    %eax,%edi
  40faee:	29 c1                	sub    %eax,%ecx
  40faf0:	c1 ef 03             	shr    $0x3,%edi
  40faf3:	31 cf                	xor    %ecx,%edi
  40faf5:	29 c2                	sub    %eax,%edx
  40faf7:	89 f9                	mov    %edi,%ecx
  40faf9:	29 fa                	sub    %edi,%edx
  40fafb:	29 f8                	sub    %edi,%eax
  40fafd:	c1 e1 0a             	shl    $0xa,%ecx
  40fb00:	31 ca                	xor    %ecx,%edx
  40fb02:	49 8b 88 e8 00 00 00 	mov    0xe8(%r8),%rcx
  40fb09:	29 d0                	sub    %edx,%eax
  40fb0b:	c1 ea 0f             	shr    $0xf,%edx
  40fb0e:	31 c2                	xor    %eax,%edx
  40fb10:	8b 41 08             	mov    0x8(%rcx),%eax
  40fb13:	48 8b 39             	mov    (%rcx),%rdi
  40fb16:	41 89 d1             	mov    %edx,%r9d
  40fb19:	83 e8 01             	sub    $0x1,%eax
  40fb1c:	21 d0                	and    %edx,%eax
  40fb1e:	48 c1 e0 04          	shl    $0x4,%rax
  40fb22:	48 8b 1c 07          	mov    (%rdi,%rax,1),%rbx
  40fb26:	48 85 db             	test   %rbx,%rbx
  40fb29:	0f 84 70 d2 ff ff    	je     40cd9f <process_udp.isra.0+0x1df>
  40fb2f:	48 8b 51 20          	mov    0x20(%rcx),%rdx
  40fb33:	48 89 d0             	mov    %rdx,%rax
  40fb36:	48 29 d3             	sub    %rdx,%rbx
  40fb39:	48 f7 d8             	neg    %rax
  40fb3c:	eb 15                	jmp    40fb53 <process_udp.isra.0+0x2f93>
  40fb3e:	66 90                	xchg   %ax,%ax
  40fb40:	48 8b 9b 08 01 00 00 	mov    0x108(%rbx),%rbx
  40fb47:	48 85 db             	test   %rbx,%rbx
  40fb4a:	0f 84 4f d2 ff ff    	je     40cd9f <process_udp.isra.0+0x1df>
  40fb50:	48 01 c3             	add    %rax,%rbx
  40fb53:	44 3b 8b 1c 01 00 00 	cmp    0x11c(%rbx),%r9d
  40fb5a:	75 e4                	jne    40fb40 <process_udp.isra.0+0x2f80>
  40fb5c:	83 bb 18 01 00 00 06 	cmpl   $0x6,0x118(%rbx)
  40fb63:	75 db                	jne    40fb40 <process_udp.isra.0+0x2f80>
  40fb65:	4c 8b 93 10 01 00 00 	mov    0x110(%rbx),%r10
  40fb6c:	45 8b 1f             	mov    (%r15),%r11d
  40fb6f:	45 39 1a             	cmp    %r11d,(%r10)
  40fb72:	75 cc                	jne    40fb40 <process_udp.isra.0+0x2f80>
  40fb74:	45 0f b7 5f 04       	movzwl 0x4(%r15),%r11d
  40fb79:	66 45 39 5a 04       	cmp    %r11w,0x4(%r10)
  40fb7e:	75 c0                	jne    40fb40 <process_udp.isra.0+0x2f80>
  40fb80:	4c 8b 9d 98 f0 ff ff 	mov    -0xf68(%rbp),%r11
  40fb87:	8b 43 34             	mov    0x34(%rbx),%eax
  40fb8a:	41 39 43 74          	cmp    %eax,0x74(%r11)
  40fb8e:	0f 84 e9 0c 00 00    	je     41087d <process_udp.isra.0+0x3cbd>
  40fb94:	85 c0                	test   %eax,%eax
  40fb96:	0f 88 e1 0c 00 00    	js     41087d <process_udp.isra.0+0x3cbd>
  40fb9c:	48 8b 85 98 f0 ff ff 	mov    -0xf68(%rbp),%rax
  40fba3:	48 8b b0 80 00 00 00 	mov    0x80(%rax),%rsi
  40fbaa:	48 85 f6             	test   %rsi,%rsi
  40fbad:	0f 84 9d e4 ff ff    	je     40e050 <process_udp.isra.0+0x1490>
  40fbb3:	0f b6 43 37          	movzbl 0x37(%rbx),%eax
  40fbb7:	0f b6 53 34          	movzbl 0x34(%rbx),%edx
  40fbbb:	b9 c6 ba 49 9f       	mov    $0x9f49bac6,%ecx
  40fbc0:	c1 e0 18             	shl    $0x18,%eax
  40fbc3:	8d 84 10 0d 41 12 01 	lea    0x112410d(%rax,%rdx,1),%eax
  40fbca:	0f b6 53 36          	movzbl 0x36(%rbx),%edx
  40fbce:	c1 e2 10             	shl    $0x10,%edx
  40fbd1:	01 d0                	add    %edx,%eax
  40fbd3:	0f b6 53 35          	movzbl 0x35(%rbx),%edx
  40fbd7:	c1 e2 08             	shl    $0x8,%edx
  40fbda:	01 d0                	add    %edx,%eax
  40fbdc:	35 6d f7 07 00       	xor    $0x7f76d,%eax
  40fbe1:	89 c2                	mov    %eax,%edx
  40fbe3:	29 c1                	sub    %eax,%ecx
  40fbe5:	c1 e2 08             	shl    $0x8,%edx
  40fbe8:	31 ca                	xor    %ecx,%edx
  40fbea:	b9 f3 be ed fe       	mov    $0xfeedbef3,%ecx
  40fbef:	29 c1                	sub    %eax,%ecx
  40fbf1:	89 d7                	mov    %edx,%edi
  40fbf3:	29 d0                	sub    %edx,%eax
  40fbf5:	29 d1                	sub    %edx,%ecx
  40fbf7:	c1 ef 0d             	shr    $0xd,%edi
  40fbfa:	31 cf                	xor    %ecx,%edi
  40fbfc:	89 f9                	mov    %edi,%ecx
  40fbfe:	29 f8                	sub    %edi,%eax
  40fc00:	c1 e9 0c             	shr    $0xc,%ecx
  40fc03:	31 c1                	xor    %eax,%ecx
  40fc05:	89 d0                	mov    %edx,%eax
  40fc07:	29 f8                	sub    %edi,%eax
  40fc09:	89 ca                	mov    %ecx,%edx
  40fc0b:	29 cf                	sub    %ecx,%edi
  40fc0d:	29 c8                	sub    %ecx,%eax
  40fc0f:	c1 e2 10             	shl    $0x10,%edx
  40fc12:	31 c2                	xor    %eax,%edx
  40fc14:	89 d0                	mov    %edx,%eax
  40fc16:	29 d7                	sub    %edx,%edi
  40fc18:	29 d1                	sub    %edx,%ecx
  40fc1a:	c1 e8 05             	shr    $0x5,%eax
  40fc1d:	31 f8                	xor    %edi,%eax
  40fc1f:	89 c7                	mov    %eax,%edi
  40fc21:	29 c1                	sub    %eax,%ecx
  40fc23:	29 c2                	sub    %eax,%edx
  40fc25:	c1 ef 03             	shr    $0x3,%edi
  40fc28:	31 cf                	xor    %ecx,%edi
  40fc2a:	89 f9                	mov    %edi,%ecx
  40fc2c:	29 fa                	sub    %edi,%edx
  40fc2e:	c1 e1 0a             	shl    $0xa,%ecx
  40fc31:	31 ca                	xor    %ecx,%edx
  40fc33:	48 8b 8e 90 08 00 00 	mov    0x890(%rsi),%rcx
  40fc3a:	29 f8                	sub    %edi,%eax
  40fc3c:	29 d0                	sub    %edx,%eax
  40fc3e:	c1 ea 0f             	shr    $0xf,%edx
  40fc41:	8b 71 08             	mov    0x8(%rcx),%esi
  40fc44:	31 d0                	xor    %edx,%eax
  40fc46:	8d 56 ff             	lea    -0x1(%rsi),%edx
  40fc49:	21 c2                	and    %eax,%edx
  40fc4b:	48 c1 e2 04          	shl    $0x4,%rdx
  40fc4f:	48 03 11             	add    (%rcx),%rdx
  40fc52:	48 8b 32             	mov    (%rdx),%rsi
  40fc55:	48 85 f6             	test   %rsi,%rsi
  40fc58:	0f 84 f2 e3 ff ff    	je     40e050 <process_udp.isra.0+0x1490>
  40fc5e:	48 8b 51 20          	mov    0x20(%rcx),%rdx
  40fc62:	48 89 d1             	mov    %rdx,%rcx
  40fc65:	48 29 d6             	sub    %rdx,%rsi
  40fc68:	48 f7 d9             	neg    %rcx
  40fc6b:	eb 16                	jmp    40fc83 <process_udp.isra.0+0x30c3>
  40fc6d:	0f 1f 00             	nopl   (%rax)
  40fc70:	48 8b b6 b0 08 00 00 	mov    0x8b0(%rsi),%rsi
  40fc77:	48 85 f6             	test   %rsi,%rsi
  40fc7a:	0f 84 d0 e3 ff ff    	je     40e050 <process_udp.isra.0+0x1490>
  40fc80:	48 01 ce             	add    %rcx,%rsi
  40fc83:	3b 86 c4 08 00 00    	cmp    0x8c4(%rsi),%eax
  40fc89:	75 e5                	jne    40fc70 <process_udp.isra.0+0x30b0>
  40fc8b:	83 be c0 08 00 00 04 	cmpl   $0x4,0x8c0(%rsi)
  40fc92:	75 dc                	jne    40fc70 <process_udp.isra.0+0x30b0>
  40fc94:	48 8b 96 b8 08 00 00 	mov    0x8b8(%rsi),%rdx
  40fc9b:	8b 12                	mov    (%rdx),%edx
  40fc9d:	39 53 34             	cmp    %edx,0x34(%rbx)
  40fca0:	75 ce                	jne    40fc70 <process_udp.isra.0+0x30b0>
  40fca2:	e9 a9 e3 ff ff       	jmp    40e050 <process_udp.isra.0+0x1490>
  40fca7:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
  40fcae:	00 00 
  40fcb0:	48 8b 85 98 f0 ff ff 	mov    -0xf68(%rbp),%rax
  40fcb7:	4c 8d b5 24 f1 ff ff 	lea    -0xedc(%rbp),%r14
  40fcbe:	8b b8 a4 00 00 00    	mov    0xa4(%rax),%edi
  40fcc4:	85 ff                	test   %edi,%edi
  40fcc6:	0f 84 ef 01 00 00    	je     40febb <process_udp.isra.0+0x32fb>
  40fccc:	48 8b 85 98 f0 ff ff 	mov    -0xf68(%rbp),%rax
  40fcd3:	4c 8d b5 24 f1 ff ff 	lea    -0xedc(%rbp),%r14
  40fcda:	48 8b 80 b8 00 00 00 	mov    0xb8(%rax),%rax
  40fce1:	48 85 c0             	test   %rax,%rax
  40fce4:	74 51                	je     40fd37 <process_udp.isra.0+0x3177>
  40fce6:	4c 8b 60 18          	mov    0x18(%rax),%r12
  40fcea:	4c 8d b5 24 f1 ff ff 	lea    -0xedc(%rbp),%r14
  40fcf1:	4c 8d ad d4 f0 ff ff 	lea    -0xf2c(%rbp),%r13
  40fcf8:	48 8b 38             	mov    (%rax),%rdi
  40fcfb:	4c 89 ea             	mov    %r13,%rdx
  40fcfe:	4c 89 f6             	mov    %r14,%rsi
  40fd01:	e8 aa f4 00 00       	call   41f1b0 <re_matchp>
  40fd06:	89 c3                	mov    %eax,%ebx
  40fd08:	3c ff                	cmp    $0xff,%al
  40fd0a:	74 1c                	je     40fd28 <process_udp.isra.0+0x3168>
  40fd0c:	4c 89 f7             	mov    %r14,%rdi
  40fd0f:	e8 9c 28 ff ff       	call   4025b0 <strlen@plt>
  40fd14:	48 63 95 d4 f0 ff ff 	movslq -0xf2c(%rbp),%rdx
  40fd1b:	48 39 c2             	cmp    %rax,%rdx
  40fd1e:	75 08                	jne    40fd28 <process_udp.isra.0+0x3168>
  40fd20:	84 db                	test   %bl,%bl
  40fd22:	0f 84 93 01 00 00    	je     40febb <process_udp.isra.0+0x32fb>
  40fd28:	4d 85 e4             	test   %r12,%r12
  40fd2b:	74 0a                	je     40fd37 <process_udp.isra.0+0x3177>
  40fd2d:	4c 89 e0             	mov    %r12,%rax
  40fd30:	4d 8b 64 24 18       	mov    0x18(%r12),%r12
  40fd35:	eb c1                	jmp    40fcf8 <process_udp.isra.0+0x3138>
  40fd37:	4d 89 f0             	mov    %r14,%r8
  40fd3a:	ba 88 07 00 00       	mov    $0x788,%edx
  40fd3f:	bf 03 00 00 00       	mov    $0x3,%edi
  40fd44:	31 c0                	xor    %eax,%eax
  40fd46:	48 8d 0d 7b 33 01 00 	lea    0x1337b(%rip),%rcx        # 4230c8 <_IO_stdin_used+0x20c8>
  40fd4d:	48 8d 35 a1 4b 01 00 	lea    0x14ba1(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40fd54:	e8 17 46 ff ff       	call   404370 <_traceEvent>
  40fd59:	e9 41 d0 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40fd5e:	48 8d 05 05 4d 01 00 	lea    0x14d05(%rip),%rax        # 424a6a <_IO_stdin_used+0x3a6a>
  40fd65:	4c 8d 05 2f 4e 01 00 	lea    0x14e2f(%rip),%r8        # 424b9b <_IO_stdin_used+0x3b9b>
  40fd6c:	50                   	push   %rax
  40fd6d:	41 56                	push   %r14
  40fd6f:	e9 0d ec ff ff       	jmp    40e981 <process_udp.isra.0+0x1dc1>
  40fd74:	80 bd 87 f0 ff ff 00 	cmpb   $0x0,-0xf79(%rbp)
  40fd7b:	4c 89 fe             	mov    %r15,%rsi
  40fd7e:	4c 89 e7             	mov    %r12,%rdi
  40fd81:	0f 84 e0 08 00 00    	je     410667 <process_udp.isra.0+0x3aa7>
  40fd87:	e8 74 4b ff ff       	call   404900 <macaddr_str>
  40fd8c:	ba c2 09 00 00       	mov    $0x9c2,%edx
  40fd91:	bf 04 00 00 00       	mov    $0x4,%edi
  40fd96:	48 8d 0d 83 37 01 00 	lea    0x13783(%rip),%rcx        # 423520 <_IO_stdin_used+0x2520>
  40fd9d:	49 89 c0             	mov    %rax,%r8
  40fda0:	48 8d 35 4e 4b 01 00 	lea    0x14b4e(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  40fda7:	31 c0                	xor    %eax,%eax
  40fda9:	e8 c2 45 ff ff       	call   404370 <_traceEvent>
  40fdae:	e9 ec cf ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  40fdb3:	48 8d 05 b8 4c 01 00 	lea    0x14cb8(%rip),%rax        # 424a72 <_IO_stdin_used+0x3a72>
  40fdba:	4c 8d 05 da 4d 01 00 	lea    0x14dda(%rip),%r8        # 424b9b <_IO_stdin_used+0x3b9b>
  40fdc1:	50                   	push   %rax
  40fdc2:	41 56                	push   %r14
  40fdc4:	e9 4b e7 ff ff       	jmp    40e514 <process_udp.isra.0+0x1954>
  40fdc9:	48 8b 85 c0 f0 ff ff 	mov    -0xf40(%rbp),%rax
  40fdd0:	4c 8d a5 d8 f0 ff ff 	lea    -0xf28(%rbp),%r12
  40fdd7:	48 8b b5 b8 f0 ff ff 	mov    -0xf48(%rbp),%rsi
  40fdde:	48 8d 8d e0 f0 ff ff 	lea    -0xf20(%rbp),%rcx
  40fde5:	4c 89 e2             	mov    %r12,%rdx
  40fde8:	48 89 8d 90 f0 ff ff 	mov    %rcx,-0xf70(%rbp)
  40fdef:	48 89 85 d8 f0 ff ff 	mov    %rax,-0xf28(%rbp)
  40fdf6:	48 8d 85 20 f1 ff ff 	lea    -0xee0(%rbp),%rax
  40fdfd:	48 89 c7             	mov    %rax,%rdi
  40fe00:	48 89 85 88 f0 ff ff 	mov    %rax,-0xf78(%rbp)
  40fe07:	48 c7 85 e0 f0 ff ff 	movq   $0x0,-0xf20(%rbp)
  40fe0e:	00 00 00 00 
  40fe12:	e8 b9 97 00 00       	call   4195d0 <decode_common>
  40fe17:	85 c0                	test   %eax,%eax
  40fe19:	0f 88 e7 0b 00 00    	js     410a06 <process_udp.isra.0+0x3e46>
  40fe1f:	44 0f b6 85 21 f1 ff 	movzbl -0xedf(%rbp),%r8d
  40fe26:	ff 
  40fe27:	48 c7 85 c8 f0 ff ff 	movq   $0x0,-0xf38(%rbp)
  40fe2e:	00 00 00 00 
  40fe32:	4c 89 c3             	mov    %r8,%rbx
  40fe35:	e9 d0 d1 ff ff       	jmp    40d00a <process_udp.isra.0+0x44a>
  40fe3a:	48 8b 85 98 f0 ff ff 	mov    -0xf68(%rbp),%rax
  40fe41:	8b 80 1c 01 00 00    	mov    0x11c(%rax),%eax
  40fe47:	3b 85 7c f2 ff ff    	cmp    -0xd84(%rbp),%eax
  40fe4d:	0f 82 26 0e 00 00    	jb     410c79 <process_udp.isra.0+0x40b9>
  40fe53:	89 85 00 f2 ff ff    	mov    %eax,-0xe00(%rbp)
  40fe59:	e9 6e f0 ff ff       	jmp    40eecc <process_udp.isra.0+0x230c>
  40fe5e:	48 8b 9d 98 f0 ff ff 	mov    -0xf68(%rbp),%rbx
  40fe65:	48 8b b5 48 f0 ff ff 	mov    -0xfb8(%rbp),%rsi
  40fe6c:	4c 89 fa             	mov    %r15,%rdx
  40fe6f:	48 8d 8d d0 f0 ff ff 	lea    -0xf30(%rbp),%rcx
  40fe76:	4c 89 95 b8 f0 ff ff 	mov    %r10,-0xf48(%rbp)
  40fe7d:	48 8b 83 c0 00 00 00 	mov    0xc0(%rbx),%rax
  40fe84:	c7 85 d0 f0 ff ff 00 	movl   $0x0,-0xf30(%rbp)
  40fe8b:	00 00 00 
  40fe8e:	48 8d 78 48          	lea    0x48(%rax),%rdi
  40fe92:	48 89 85 c0 f0 ff ff 	mov    %rax,-0xf40(%rbp)
  40fe99:	e8 62 5a ff ff       	call   405900 <add_sn_to_list_by_mac_or_sock>
  40fe9e:	48 8b 75 10          	mov    0x10(%rbp),%rsi
  40fea2:	8b 53 74             	mov    0x74(%rbx),%edx
  40fea5:	4c 8b 95 b8 f0 ff ff 	mov    -0xf48(%rbp),%r10
  40feac:	48 89 b0 90 00 00 00 	mov    %rsi,0x90(%rax)
  40feb3:	89 50 34             	mov    %edx,0x34(%rax)
  40feb6:	e9 3f ed ff ff       	jmp    40ebfa <process_udp.isra.0+0x203a>
  40febb:	be a8 00 00 00       	mov    $0xa8,%esi
  40fec0:	bf 01 00 00 00       	mov    $0x1,%edi
  40fec5:	e8 c6 27 ff ff       	call   402690 <calloc@plt>
  40feca:	48 89 85 c8 f0 ff ff 	mov    %rax,-0xf38(%rbp)
  40fed1:	48 89 c3             	mov    %rax,%rbx
  40fed4:	48 85 c0             	test   %rax,%rax
  40fed7:	0f 84 c2 10 00 00    	je     410f9f <process_udp.isra.0+0x43df>
  40fedd:	ba 13 00 00 00       	mov    $0x13,%edx
  40fee2:	4c 89 f6             	mov    %r14,%rsi
  40fee5:	48 89 c7             	mov    %rax,%rdi
  40fee8:	e8 43 26 ff ff       	call   402530 <strncpy@plt>
  40feed:	c7 43 13 00 00 01 01 	movl   $0x1010000,0x13(%rbx)
  40fef4:	66 0f ef c0          	pxor   %xmm0,%xmm0
  40fef8:	48 89 df             	mov    %rbx,%rdi
  40fefb:	48 c7 43 60 00 00 00 	movq   $0x0,0x60(%rbx)
  40ff02:	00 
  40ff03:	0f 11 43 18          	movups %xmm0,0x18(%rbx)
  40ff07:	e8 a4 26 ff ff       	call   4025b0 <strlen@plt>
  40ff0c:	49 89 c1             	mov    %rax,%r9
  40ff0f:	83 f8 0b             	cmp    $0xb,%eax
  40ff12:	0f 86 52 10 00 00    	jbe    410f6a <process_udp.isra.0+0x43aa>
  40ff18:	41 89 c0             	mov    %eax,%r8d
  40ff1b:	48 89 df             	mov    %rbx,%rdi
  40ff1e:	be ef be ed fe       	mov    $0xfeedbeef,%esi
  40ff23:	ba b9 79 37 9e       	mov    $0x9e3779b9,%edx
  40ff28:	b9 b9 79 37 9e       	mov    $0x9e3779b9,%ecx
  40ff2d:	0f b6 47 05          	movzbl 0x5(%rdi),%eax
  40ff31:	44 0f b6 57 06       	movzbl 0x6(%rdi),%r10d
  40ff36:	c1 e0 08             	shl    $0x8,%eax
  40ff39:	41 c1 e2 10          	shl    $0x10,%r10d
  40ff3d:	44 01 d0             	add    %r10d,%eax
  40ff40:	44 0f b6 57 04       	movzbl 0x4(%rdi),%r10d
  40ff45:	44 01 d0             	add    %r10d,%eax
  40ff48:	44 0f b6 57 07       	movzbl 0x7(%rdi),%r10d
  40ff4d:	41 c1 e2 18          	shl    $0x18,%r10d
  40ff51:	44 01 d0             	add    %r10d,%eax
  40ff54:	44 0f b6 57 0a       	movzbl 0xa(%rdi),%r10d
  40ff59:	01 c2                	add    %eax,%edx
  40ff5b:	0f b6 47 09          	movzbl 0x9(%rdi),%eax
  40ff5f:	41 c1 e2 10          	shl    $0x10,%r10d
  40ff63:	c1 e0 08             	shl    $0x8,%eax
  40ff66:	44 01 d0             	add    %r10d,%eax
  40ff69:	44 0f b6 57 08       	movzbl 0x8(%rdi),%r10d
  40ff6e:	44 01 d0             	add    %r10d,%eax
  40ff71:	44 0f b6 57 0b       	movzbl 0xb(%rdi),%r10d
  40ff76:	41 c1 e2 18          	shl    $0x18,%r10d
  40ff7a:	44 01 d0             	add    %r10d,%eax
  40ff7d:	44 0f b6 57 02       	movzbl 0x2(%rdi),%r10d
  40ff82:	01 f0                	add    %esi,%eax
  40ff84:	0f b6 77 01          	movzbl 0x1(%rdi),%esi
  40ff88:	41 c1 e2 10          	shl    $0x10,%r10d
  40ff8c:	c1 e6 08             	shl    $0x8,%esi
  40ff8f:	44 01 d6             	add    %r10d,%esi
  40ff92:	44 0f b6 17          	movzbl (%rdi),%r10d
  40ff96:	44 01 d6             	add    %r10d,%esi
  40ff99:	44 0f b6 57 03       	movzbl 0x3(%rdi),%r10d
  40ff9e:	41 c1 e2 18          	shl    $0x18,%r10d
  40ffa2:	44 01 d6             	add    %r10d,%esi
  40ffa5:	29 d6                	sub    %edx,%esi
  40ffa7:	29 c2                	sub    %eax,%edx
  40ffa9:	29 c6                	sub    %eax,%esi
  40ffab:	01 f1                	add    %esi,%ecx
  40ffad:	89 c6                	mov    %eax,%esi
  40ffaf:	c1 ee 0d             	shr    $0xd,%esi
  40ffb2:	31 f1                	xor    %esi,%ecx
  40ffb4:	89 d6                	mov    %edx,%esi
  40ffb6:	89 ca                	mov    %ecx,%edx
  40ffb8:	29 ce                	sub    %ecx,%esi
  40ffba:	29 c8                	sub    %ecx,%eax
  40ffbc:	c1 e2 08             	shl    $0x8,%edx
  40ffbf:	31 f2                	xor    %esi,%edx
  40ffc1:	29 d0                	sub    %edx,%eax
  40ffc3:	89 c6                	mov    %eax,%esi
  40ffc5:	89 d0                	mov    %edx,%eax
  40ffc7:	c1 e8 0d             	shr    $0xd,%eax
  40ffca:	31 f0                	xor    %esi,%eax
  40ffcc:	29 d1                	sub    %edx,%ecx
  40ffce:	41 83 e8 0c          	sub    $0xc,%r8d
  40ffd2:	48 83 c7 0c          	add    $0xc,%rdi
  40ffd6:	89 ce                	mov    %ecx,%esi
  40ffd8:	89 c1                	mov    %eax,%ecx
  40ffda:	29 c2                	sub    %eax,%edx
  40ffdc:	29 c6                	sub    %eax,%esi
  40ffde:	c1 e9 0c             	shr    $0xc,%ecx
  40ffe1:	31 f1                	xor    %esi,%ecx
  40ffe3:	89 d6                	mov    %edx,%esi
  40ffe5:	89 ca                	mov    %ecx,%edx
  40ffe7:	29 ce                	sub    %ecx,%esi
  40ffe9:	29 c8                	sub    %ecx,%eax
  40ffeb:	c1 e2 10             	shl    $0x10,%edx
  40ffee:	31 f2                	xor    %esi,%edx
  40fff0:	29 d0                	sub    %edx,%eax
  40fff2:	29 d1                	sub    %edx,%ecx
  40fff4:	89 c6                	mov    %eax,%esi
  40fff6:	89 d0                	mov    %edx,%eax
  40fff8:	c1 e8 05             	shr    $0x5,%eax
  40fffb:	31 f0                	xor    %esi,%eax
  40fffd:	89 ce                	mov    %ecx,%esi
  40ffff:	89 c1                	mov    %eax,%ecx
  410001:	29 c6                	sub    %eax,%esi
  410003:	29 c2                	sub    %eax,%edx
  410005:	c1 e9 03             	shr    $0x3,%ecx
  410008:	31 f1                	xor    %esi,%ecx
  41000a:	89 ce                	mov    %ecx,%esi
  41000c:	29 ca                	sub    %ecx,%edx
  41000e:	29 c8                	sub    %ecx,%eax
  410010:	c1 e6 0a             	shl    $0xa,%esi
  410013:	31 f2                	xor    %esi,%edx
  410015:	89 d6                	mov    %edx,%esi
  410017:	29 d0                	sub    %edx,%eax
  410019:	c1 ee 0f             	shr    $0xf,%esi
  41001c:	31 c6                	xor    %eax,%esi
  41001e:	41 83 f8 0b          	cmp    $0xb,%r8d
  410022:	0f 87 05 ff ff ff    	ja     40ff2d <process_udp.isra.0+0x336d>
  410028:	44 01 ce             	add    %r9d,%esi
  41002b:	41 83 f8 0b          	cmp    $0xb,%r8d
  41002f:	0f 87 a7 02 00 00    	ja     4102dc <process_udp.isra.0+0x371c>
  410035:	4c 8d 1d 78 54 01 00 	lea    0x15478(%rip),%r11        # 4254b4 <ftbl+0x114>
  41003c:	4b 63 04 83          	movslq (%r11,%r8,4),%rax
  410040:	4c 01 d8             	add    %r11,%rax
  410043:	3e ff e0             	notrack jmp *%rax
  410046:	48 8b 8d c8 f0 ff ff 	mov    -0xf38(%rbp),%rcx
  41004d:	49 8b bc 24 f0 00 00 	mov    0xf0(%r12),%rdi
  410054:	00 
  410055:	49 8d b4 24 e8 00 00 	lea    0xe8(%r12),%rsi
  41005c:	00 
  41005d:	49 8b 84 24 f8 00 00 	mov    0xf8(%r12),%rax
  410064:	00 
  410065:	48 8b 49 48          	mov    0x48(%rcx),%rcx
  410069:	48 8b 91 e8 00 00 00 	mov    0xe8(%rcx),%rdx
  410070:	48 85 ff             	test   %rdi,%rdi
  410073:	0f 84 b6 0b 00 00    	je     410c2f <process_udp.isra.0+0x406f>
  410079:	4c 8b 42 20          	mov    0x20(%rdx),%r8
  41007d:	49 01 f8             	add    %rdi,%r8
  410080:	48 3b 72 18          	cmp    0x18(%rdx),%rsi
  410084:	0f 84 9c 0b 00 00    	je     410c26 <process_udp.isra.0+0x4066>
  41008a:	49 89 40 10          	mov    %rax,0x10(%r8)
  41008e:	49 8b 84 24 f8 00 00 	mov    0xf8(%r12),%rax
  410095:	00 
  410096:	48 85 c0             	test   %rax,%rax
  410099:	74 10                	je     4100ab <process_udp.isra.0+0x34eb>
  41009b:	48 8b 91 e8 00 00 00 	mov    0xe8(%rcx),%rdx
  4100a2:	48 8b 52 20          	mov    0x20(%rdx),%rdx
  4100a6:	48 89 7c 10 08       	mov    %rdi,0x8(%rax,%rdx,1)
  4100ab:	48 8b 89 e8 00 00 00 	mov    0xe8(%rcx),%rcx
  4100b2:	49 8b 94 24 08 01 00 	mov    0x108(%r12),%rdx
  4100b9:	00 
  4100ba:	8b 41 08             	mov    0x8(%rcx),%eax
  4100bd:	83 e8 01             	sub    $0x1,%eax
  4100c0:	41 23 84 24 1c 01 00 	and    0x11c(%r12),%eax
  4100c7:	00 
  4100c8:	48 c1 e0 04          	shl    $0x4,%rax
  4100cc:	48 03 01             	add    (%rcx),%rax
  4100cf:	83 68 08 01          	subl   $0x1,0x8(%rax)
  4100d3:	48 3b 30             	cmp    (%rax),%rsi
  4100d6:	0f 84 42 0b 00 00    	je     410c1e <process_udp.isra.0+0x405e>
  4100dc:	49 8b 84 24 00 01 00 	mov    0x100(%r12),%rax
  4100e3:	00 
  4100e4:	48 85 c0             	test   %rax,%rax
  4100e7:	74 0c                	je     4100f5 <process_udp.isra.0+0x3535>
  4100e9:	48 89 50 20          	mov    %rdx,0x20(%rax)
  4100ed:	49 8b 94 24 08 01 00 	mov    0x108(%r12),%rdx
  4100f4:	00 
  4100f5:	48 85 d2             	test   %rdx,%rdx
  4100f8:	74 04                	je     4100fe <process_udp.isra.0+0x353e>
  4100fa:	48 89 42 18          	mov    %rax,0x18(%rdx)
  4100fe:	83 69 10 01          	subl   $0x1,0x10(%rcx)
  410102:	4c 89 e7             	mov    %r12,%rdi
  410105:	e8 d6 23 ff ff       	call   4024e0 <free@plt>
  41010a:	e9 90 cc ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  41010f:	48 8d 0d 8a 32 01 00 	lea    0x1328a(%rip),%rcx        # 4233a0 <_IO_stdin_used+0x23a0>
  410116:	ba d5 08 00 00       	mov    $0x8d5,%edx
  41011b:	48 8d 35 d3 47 01 00 	lea    0x147d3(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  410122:	31 c0                	xor    %eax,%eax
  410124:	bf 04 00 00 00       	mov    $0x4,%edi
  410129:	e8 42 42 ff ff       	call   404370 <_traceEvent>
  41012e:	e9 6c cc ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  410133:	48 8b be f8 00 00 00 	mov    0xf8(%rsi),%rdi
  41013a:	89 c2                	mov    %eax,%edx
  41013c:	49 89 f0             	mov    %rsi,%r8
  41013f:	48 89 f9             	mov    %rdi,%rcx
  410142:	41 3b 50 08          	cmp    0x8(%r8),%edx
  410146:	0f 82 44 f6 ff ff    	jb     40f790 <process_udp.isra.0+0x2bd0>
  41014c:	74 1f                	je     41016d <process_udp.isra.0+0x35ad>
  41014e:	48 85 c9             	test   %rcx,%rcx
  410151:	0f 84 39 f6 ff ff    	je     40f790 <process_udp.isra.0+0x2bd0>
  410157:	49 89 c8             	mov    %rcx,%r8
  41015a:	48 8b 89 f8 00 00 00 	mov    0xf8(%rcx),%rcx
  410161:	41 3b 50 08          	cmp    0x8(%r8),%edx
  410165:	0f 82 25 f6 ff ff    	jb     40f790 <process_udp.isra.0+0x2bd0>
  41016b:	75 e1                	jne    41014e <process_udp.isra.0+0x358e>
  41016d:	8d 4a ff             	lea    -0x1(%rdx),%ecx
  410170:	41 39 ce             	cmp    %ecx,%r14d
  410173:	0f 84 e0 f5 ff ff    	je     40f759 <process_udp.isra.0+0x2b99>
  410179:	89 ca                	mov    %ecx,%edx
  41017b:	eb bf                	jmp    41013c <process_udp.isra.0+0x357c>
  41017d:	8b 85 10 f1 ff ff    	mov    -0xef0(%rbp),%eax
  410183:	66 0f 6f 9d 00 f1 ff 	movdqa -0xf00(%rbp),%xmm3
  41018a:	ff 
  41018b:	48 8d 9d 40 f1 ff ff 	lea    -0xec0(%rbp),%rbx
  410192:	4c 8d ad f0 f0 ff ff 	lea    -0xf10(%rbp),%r13
  410199:	48 8b 8d 60 f0 ff ff 	mov    -0xfa0(%rbp),%rcx
  4101a0:	48 89 da             	mov    %rbx,%rdx
  4101a3:	4c 89 ee             	mov    %r13,%rsi
  4101a6:	4c 89 95 b8 f0 ff ff 	mov    %r10,-0xf48(%rbp)
  4101ad:	89 85 2a f2 ff ff    	mov    %eax,-0xdd6(%rbp)
  4101b3:	48 8d 85 c0 f7 ff ff 	lea    -0x840(%rbp),%rax
  4101ba:	48 89 c7             	mov    %rax,%rdi
  4101bd:	c6 85 41 f1 ff ff 05 	movb   $0x5,-0xebf(%rbp)
  4101c4:	48 89 85 c0 f0 ff ff 	mov    %rax,-0xf40(%rbp)
  4101cb:	0f 11 9d 1a f2 ff ff 	movups %xmm3,-0xde6(%rbp)
  4101d2:	e8 89 9a 00 00       	call   419c60 <encode_REGISTER_SUPER>
  4101d7:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  4101de:	4c 8b 95 b8 f0 ff ff 	mov    -0xf48(%rbp),%r10
  4101e5:	80 78 16 02          	cmpb   $0x2,0x16(%rax)
  4101e9:	0f 84 30 0b 00 00    	je     410d1f <process_udp.isra.0+0x415f>
  4101ef:	48 83 ec 08          	sub    $0x8,%rsp
  4101f3:	4c 89 95 b8 f0 ff ff 	mov    %r10,-0xf48(%rbp)
  4101fa:	4c 89 fa             	mov    %r15,%rdx
  4101fd:	31 f6                	xor    %esi,%esi
  4101ff:	0f b6 8d 87 f0 ff ff 	movzbl -0xf79(%rbp),%ecx
  410206:	ff 75 10             	push   0x10(%rbp)
  410209:	4c 8b 85 c0 f0 ff ff 	mov    -0xf40(%rbp),%r8
  410210:	4c 8b 8d f0 f0 ff ff 	mov    -0xf10(%rbp),%r9
  410217:	48 8b bd 98 f0 ff ff 	mov    -0xf68(%rbp),%rdi
  41021e:	e8 ad 91 ff ff       	call   4093d0 <try_broadcast.isra.0>
  410223:	58                   	pop    %rax
  410224:	4c 8b 95 b8 f0 ff ff 	mov    -0xf48(%rbp),%r10
  41022b:	5a                   	pop    %rdx
  41022c:	e9 80 ec ff ff       	jmp    40eeb1 <process_udp.isra.0+0x22f1>
  410231:	48 8b 78 48          	mov    0x48(%rax),%rdi
  410235:	41 b8 01 00 00 00    	mov    $0x1,%r8d
  41023b:	4c 89 fa             	mov    %r15,%rdx
  41023e:	4c 89 f6             	mov    %r14,%rsi
  410241:	48 8b 8d e8 f0 ff ff 	mov    -0xf18(%rbp),%rcx
  410248:	e8 c3 76 ff ff       	call   407910 <find_edge_time_stamp_and_verify>
  41024d:	85 c0                	test   %eax,%eax
  41024f:	0f 85 31 cf ff ff    	jne    40d186 <process_udp.isra.0+0x5c6>
  410255:	48 8d 0d 6c 32 01 00 	lea    0x1326c(%rip),%rcx        # 4234c8 <_IO_stdin_used+0x24c8>
  41025c:	ba 6c 09 00 00       	mov    $0x96c,%edx
  410261:	bf 04 00 00 00       	mov    $0x4,%edi
  410266:	48 8d 35 88 46 01 00 	lea    0x14688(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  41026d:	e8 fe 40 ff ff       	call   404370 <_traceEvent>
  410272:	e9 28 cb ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  410277:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
  41027e:	00 00 
  410280:	0f b6 47 0a          	movzbl 0xa(%rdi),%eax
  410284:	c1 e0 18             	shl    $0x18,%eax
  410287:	01 c6                	add    %eax,%esi
  410289:	0f b6 47 09          	movzbl 0x9(%rdi),%eax
  41028d:	c1 e0 10             	shl    $0x10,%eax
  410290:	01 c6                	add    %eax,%esi
  410292:	0f b6 47 08          	movzbl 0x8(%rdi),%eax
  410296:	c1 e0 08             	shl    $0x8,%eax
  410299:	01 c6                	add    %eax,%esi
  41029b:	0f b6 47 07          	movzbl 0x7(%rdi),%eax
  41029f:	c1 e0 18             	shl    $0x18,%eax
  4102a2:	01 c2                	add    %eax,%edx
  4102a4:	0f b6 47 06          	movzbl 0x6(%rdi),%eax
  4102a8:	c1 e0 10             	shl    $0x10,%eax
  4102ab:	01 c2                	add    %eax,%edx
  4102ad:	0f b6 47 05          	movzbl 0x5(%rdi),%eax
  4102b1:	c1 e0 08             	shl    $0x8,%eax
  4102b4:	01 c2                	add    %eax,%edx
  4102b6:	0f b6 47 04          	movzbl 0x4(%rdi),%eax
  4102ba:	01 c2                	add    %eax,%edx
  4102bc:	0f b6 47 03          	movzbl 0x3(%rdi),%eax
  4102c0:	c1 e0 18             	shl    $0x18,%eax
  4102c3:	01 c1                	add    %eax,%ecx
  4102c5:	0f b6 47 02          	movzbl 0x2(%rdi),%eax
  4102c9:	c1 e0 10             	shl    $0x10,%eax
  4102cc:	01 c1                	add    %eax,%ecx
  4102ce:	0f b6 47 01          	movzbl 0x1(%rdi),%eax
  4102d2:	c1 e0 08             	shl    $0x8,%eax
  4102d5:	01 c1                	add    %eax,%ecx
  4102d7:	0f b6 07             	movzbl (%rdi),%eax
  4102da:	01 c1                	add    %eax,%ecx
  4102dc:	8d 04 32             	lea    (%rdx,%rsi,1),%eax
  4102df:	29 f2                	sub    %esi,%edx
  4102e1:	29 c1                	sub    %eax,%ecx
  4102e3:	89 f0                	mov    %esi,%eax
  4102e5:	c1 e8 0d             	shr    $0xd,%eax
  4102e8:	31 c1                	xor    %eax,%ecx
  4102ea:	89 d0                	mov    %edx,%eax
  4102ec:	89 ca                	mov    %ecx,%edx
  4102ee:	29 c8                	sub    %ecx,%eax
  4102f0:	c1 e2 08             	shl    $0x8,%edx
  4102f3:	31 c2                	xor    %eax,%edx
  4102f5:	89 f0                	mov    %esi,%eax
  4102f7:	29 c8                	sub    %ecx,%eax
  4102f9:	89 d6                	mov    %edx,%esi
  4102fb:	29 d1                	sub    %edx,%ecx
  4102fd:	29 d0                	sub    %edx,%eax
  4102ff:	c1 ee 0d             	shr    $0xd,%esi
  410302:	31 f0                	xor    %esi,%eax
  410304:	89 c6                	mov    %eax,%esi
  410306:	29 c1                	sub    %eax,%ecx
  410308:	29 c2                	sub    %eax,%edx
  41030a:	c1 ee 0c             	shr    $0xc,%esi
  41030d:	31 f1                	xor    %esi,%ecx
  41030f:	89 ce                	mov    %ecx,%esi
  410311:	29 ca                	sub    %ecx,%edx
  410313:	29 c8                	sub    %ecx,%eax
  410315:	c1 e6 10             	shl    $0x10,%esi
  410318:	31 f2                	xor    %esi,%edx
  41031a:	89 d6                	mov    %edx,%esi
  41031c:	29 d0                	sub    %edx,%eax
  41031e:	29 d1                	sub    %edx,%ecx
  410320:	c1 ee 05             	shr    $0x5,%esi
  410323:	31 f0                	xor    %esi,%eax
  410325:	89 c6                	mov    %eax,%esi
  410327:	29 c1                	sub    %eax,%ecx
  410329:	29 c2                	sub    %eax,%edx
  41032b:	c1 ee 03             	shr    $0x3,%esi
  41032e:	31 f1                	xor    %esi,%ecx
  410330:	89 ce                	mov    %ecx,%esi
  410332:	29 ca                	sub    %ecx,%edx
  410334:	29 c8                	sub    %ecx,%eax
  410336:	c1 e6 0a             	shl    $0xa,%esi
  410339:	31 f2                	xor    %esi,%edx
  41033b:	29 d0                	sub    %edx,%eax
  41033d:	c1 ea 0f             	shr    $0xf,%edx
  410340:	31 c2                	xor    %eax,%edx
  410342:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  410349:	41 89 d4             	mov    %edx,%r12d
  41034c:	89 90 a4 00 00 00    	mov    %edx,0xa4(%rax)
  410352:	48 89 80 98 00 00 00 	mov    %rax,0x98(%rax)
  410359:	44 89 88 a0 00 00 00 	mov    %r9d,0xa0(%rax)
  410360:	48 8b 85 98 f0 ff ff 	mov    -0xf68(%rbp),%rax
  410367:	48 8b 90 b0 00 00 00 	mov    0xb0(%rax),%rdx
  41036e:	48 85 d2             	test   %rdx,%rdx
  410371:	0f 84 b0 06 00 00    	je     410a27 <process_udp.isra.0+0x3e67>
  410377:	48 8b 42 70          	mov    0x70(%rdx),%rax
  41037b:	48 8b 9d c8 f0 ff ff 	mov    -0xf38(%rbp),%rbx
  410382:	48 8b 48 18          	mov    0x18(%rax),%rcx
  410386:	66 48 0f 6e c0       	movq   %rax,%xmm0
  41038b:	4c 8d 73 70          	lea    0x70(%rbx),%r14
  41038f:	48 c7 83 80 00 00 00 	movq   $0x0,0x80(%rbx)
  410396:	00 00 00 00 
  41039a:	48 89 ce             	mov    %rcx,%rsi
  41039d:	48 2b 70 20          	sub    0x20(%rax),%rsi
  4103a1:	66 48 0f 6e fe       	movq   %rsi,%xmm7
  4103a6:	66 0f 6c c7          	punpcklqdq %xmm7,%xmm0
  4103aa:	0f 11 43 70          	movups %xmm0,0x70(%rbx)
  4103ae:	48 89 59 10          	mov    %rbx,0x10(%rcx)
  4103b2:	48 8b 5a 70          	mov    0x70(%rdx),%rbx
  4103b6:	4c 89 70 18          	mov    %r14,0x18(%rax)
  4103ba:	8b 43 10             	mov    0x10(%rbx),%eax
  4103bd:	8d 48 01             	lea    0x1(%rax),%ecx
  4103c0:	8b 43 08             	mov    0x8(%rbx),%eax
  4103c3:	8d 50 ff             	lea    -0x1(%rax),%edx
  4103c6:	48 8b 03             	mov    (%rbx),%rax
  4103c9:	44 21 e2             	and    %r12d,%edx
  4103cc:	89 4b 10             	mov    %ecx,0x10(%rbx)
  4103cf:	48 c1 e2 04          	shl    $0x4,%rdx
  4103d3:	48 01 d0             	add    %rdx,%rax
  4103d6:	8b 70 08             	mov    0x8(%rax),%esi
  4103d9:	48 8b 08             	mov    (%rax),%rcx
  4103dc:	8d 56 01             	lea    0x1(%rsi),%edx
  4103df:	48 8b b5 c8 f0 ff ff 	mov    -0xf38(%rbp),%rsi
  4103e6:	89 50 08             	mov    %edx,0x8(%rax)
  4103e9:	48 89 8e 90 00 00 00 	mov    %rcx,0x90(%rsi)
  4103f0:	48 c7 86 88 00 00 00 	movq   $0x0,0x88(%rsi)
  4103f7:	00 00 00 00 
  4103fb:	48 85 c9             	test   %rcx,%rcx
  4103fe:	74 04                	je     410404 <process_udp.isra.0+0x3844>
  410400:	4c 89 71 18          	mov    %r14,0x18(%rcx)
  410404:	4c 89 30             	mov    %r14,(%rax)
  410407:	8b 40 0c             	mov    0xc(%rax),%eax
  41040a:	8d 44 80 05          	lea    0x5(%rax,%rax,4),%eax
  41040e:	01 c0                	add    %eax,%eax
  410410:	39 c2                	cmp    %eax,%edx
  410412:	72 18                	jb     41042c <process_udp.isra.0+0x386c>
  410414:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  41041b:	4c 8b 60 70          	mov    0x70(%rax),%r12
  41041f:	41 8b 74 24 34       	mov    0x34(%r12),%esi
  410424:	85 f6                	test   %esi,%esi
  410426:	0f 84 96 06 00 00    	je     410ac2 <process_udp.isra.0+0x3f02>
  41042c:	48 8b 9d c8 f0 ff ff 	mov    -0xf38(%rbp),%rbx
  410433:	48 8d 0d 7b 46 01 00 	lea    0x1467b(%rip),%rcx        # 424ab5 <_IO_stdin_used+0x3ab5>
  41043a:	31 c0                	xor    %eax,%eax
  41043c:	ba 9c 07 00 00       	mov    $0x79c,%edx
  410441:	48 8d 35 ad 44 01 00 	lea    0x144ad(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  410448:	bf 03 00 00 00       	mov    $0x3,%edi
  41044d:	49 89 d8             	mov    %rbx,%r8
  410450:	e8 1b 3f ff ff       	call   404370 <_traceEvent>
  410455:	48 8b bd 98 f0 ff ff 	mov    -0xf68(%rbp),%rdi
  41045c:	48 89 de             	mov    %rbx,%rsi
  41045f:	e8 7c aa ff ff       	call   40aee0 <assign_one_ip_subnet>
  410464:	e9 a7 dc ff ff       	jmp    40e110 <process_udp.isra.0+0x1550>
  410469:	8b 85 10 f2 ff ff    	mov    -0xdf0(%rbp),%eax
  41046f:	48 8d 9d f0 f0 ff ff 	lea    -0xf10(%rbp),%rbx
  410476:	48 8d 8d 60 f1 ff ff 	lea    -0xea0(%rbp),%rcx
  41047d:	c6 85 41 f1 ff ff 08 	movb   $0x8,-0xebf(%rbp)
  410484:	48 8d 95 40 f1 ff ff 	lea    -0xec0(%rbp),%rdx
  41048b:	48 89 de             	mov    %rbx,%rsi
  41048e:	89 85 60 f1 ff ff    	mov    %eax,-0xea0(%rbp)
  410494:	8b 85 14 f2 ff ff    	mov    -0xdec(%rbp),%eax
  41049a:	89 85 64 f1 ff ff    	mov    %eax,-0xe9c(%rbp)
  4104a0:	0f b7 85 18 f2 ff ff 	movzwl -0xde8(%rbp),%eax
  4104a7:	66 89 85 68 f1 ff ff 	mov    %ax,-0xe98(%rbp)
  4104ae:	48 8d 85 c0 f7 ff ff 	lea    -0x840(%rbp),%rax
  4104b5:	48 89 c7             	mov    %rax,%rdi
  4104b8:	48 89 85 c0 f0 ff ff 	mov    %rax,-0xf40(%rbp)
  4104bf:	e8 ec a4 00 00       	call   41a9b0 <encode_REGISTER_SUPER_NAK>
  4104c4:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  4104cb:	80 78 16 02          	cmpb   $0x2,0x16(%rax)
  4104cf:	0f 84 db 04 00 00    	je     4109b0 <process_udp.isra.0+0x3df0>
  4104d5:	4c 8b 85 f0 f0 ff ff 	mov    -0xf10(%rbp),%r8
  4104dc:	48 8b 8d c0 f0 ff ff 	mov    -0xf40(%rbp),%rcx
  4104e3:	48 8b 95 78 f0 ff ff 	mov    -0xf88(%rbp),%rdx
  4104ea:	8b b5 80 f0 ff ff    	mov    -0xf80(%rbp),%esi
  4104f0:	48 8b bd 98 f0 ff ff 	mov    -0xf68(%rbp),%rdi
  4104f7:	e8 44 8a ff ff       	call   408f40 <sendto_sock>
  4104fc:	4c 89 fe             	mov    %r15,%rsi
  4104ff:	4c 89 e7             	mov    %r12,%rdi
  410502:	e8 f9 43 ff ff       	call   404900 <macaddr_str>
  410507:	ba 1c 08 00 00       	mov    $0x81c,%edx
  41050c:	bf 04 00 00 00       	mov    $0x4,%edi
  410511:	48 8d 0d cd 45 01 00 	lea    0x145cd(%rip),%rcx        # 424ae5 <_IO_stdin_used+0x3ae5>
  410518:	49 89 c0             	mov    %rax,%r8
  41051b:	48 8d 35 d3 43 01 00 	lea    0x143d3(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  410522:	31 c0                	xor    %eax,%eax
  410524:	e8 47 3e ff ff       	call   404370 <_traceEvent>
  410529:	e9 71 c8 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  41052e:	4c 8b 87 f8 00 00 00 	mov    0xf8(%rdi),%r8
  410535:	48 89 f9             	mov    %rdi,%rcx
  410538:	4c 89 c0             	mov    %r8,%rax
  41053b:	3b 51 08             	cmp    0x8(%rcx),%edx
  41053e:	0f 82 4c f2 ff ff    	jb     40f790 <process_udp.isra.0+0x2bd0>
  410544:	0f 1f 40 00          	nopl   0x0(%rax)
  410548:	74 1d                	je     410567 <process_udp.isra.0+0x39a7>
  41054a:	48 85 c0             	test   %rax,%rax
  41054d:	0f 84 3d f2 ff ff    	je     40f790 <process_udp.isra.0+0x2bd0>
  410553:	48 89 c1             	mov    %rax,%rcx
  410556:	48 8b 80 f8 00 00 00 	mov    0xf8(%rax),%rax
  41055d:	3b 51 08             	cmp    0x8(%rcx),%edx
  410560:	73 e6                	jae    410548 <process_udp.isra.0+0x3988>
  410562:	e9 29 f2 ff ff       	jmp    40f790 <process_udp.isra.0+0x2bd0>
  410567:	8d 42 01             	lea    0x1(%rdx),%eax
  41056a:	39 f0                	cmp    %esi,%eax
  41056c:	0f 83 06 04 00 00    	jae    410978 <process_udp.isra.0+0x3db8>
  410572:	89 c2                	mov    %eax,%edx
  410574:	eb bf                	jmp    410535 <process_udp.isra.0+0x3975>
  410576:	e8 b5 52 ff ff       	call   405830 <time_stamp>
  41057b:	0f b7 b5 f8 f0 ff ff 	movzwl -0xf08(%rbp),%esi
  410582:	48 8b bd b8 f0 ff ff 	mov    -0xf48(%rbp),%rdi
  410589:	49 89 c1             	mov    %rax,%r9
  41058c:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  410593:	89 f2                	mov    %esi,%edx
  410595:	48 8b 48 20          	mov    0x20(%rax),%rcx
  410599:	4c 8b 40 30          	mov    0x30(%rax),%r8
  41059d:	e8 ae dc 00 00       	call   41e250 <packet_header_encrypt>
  4105a2:	e9 ad e1 ff ff       	jmp    40e754 <process_udp.isra.0+0x1b94>
  4105a7:	48 8b 8d c8 f0 ff ff 	mov    -0xf38(%rbp),%rcx
  4105ae:	48 8b bb f0 00 00 00 	mov    0xf0(%rbx),%rdi
  4105b5:	48 8d b3 e8 00 00 00 	lea    0xe8(%rbx),%rsi
  4105bc:	48 8b 83 f8 00 00 00 	mov    0xf8(%rbx),%rax
  4105c3:	48 8b 49 48          	mov    0x48(%rcx),%rcx
  4105c7:	48 8b 91 e8 00 00 00 	mov    0xe8(%rcx),%rdx
  4105ce:	48 85 ff             	test   %rdi,%rdi
  4105d1:	0f 84 21 06 00 00    	je     410bf8 <process_udp.isra.0+0x4038>
  4105d7:	4c 8b 42 20          	mov    0x20(%rdx),%r8
  4105db:	49 01 f8             	add    %rdi,%r8
  4105de:	48 3b 72 18          	cmp    0x18(%rdx),%rsi
  4105e2:	0f 84 87 03 00 00    	je     41096f <process_udp.isra.0+0x3daf>
  4105e8:	49 89 40 10          	mov    %rax,0x10(%r8)
  4105ec:	48 8b 83 f8 00 00 00 	mov    0xf8(%rbx),%rax
  4105f3:	48 85 c0             	test   %rax,%rax
  4105f6:	74 10                	je     410608 <process_udp.isra.0+0x3a48>
  4105f8:	48 8b 91 e8 00 00 00 	mov    0xe8(%rcx),%rdx
  4105ff:	48 8b 52 20          	mov    0x20(%rdx),%rdx
  410603:	48 89 7c 10 08       	mov    %rdi,0x8(%rax,%rdx,1)
  410608:	48 8b 89 e8 00 00 00 	mov    0xe8(%rcx),%rcx
  41060f:	48 8b 93 08 01 00 00 	mov    0x108(%rbx),%rdx
  410616:	8b 41 08             	mov    0x8(%rcx),%eax
  410619:	83 e8 01             	sub    $0x1,%eax
  41061c:	23 83 1c 01 00 00    	and    0x11c(%rbx),%eax
  410622:	48 c1 e0 04          	shl    $0x4,%rax
  410626:	48 03 01             	add    (%rcx),%rax
  410629:	83 68 08 01          	subl   $0x1,0x8(%rax)
  41062d:	48 3b 30             	cmp    (%rax),%rsi
  410630:	0f 84 b5 02 00 00    	je     4108eb <process_udp.isra.0+0x3d2b>
  410636:	48 8b 83 00 01 00 00 	mov    0x100(%rbx),%rax
  41063d:	48 85 c0             	test   %rax,%rax
  410640:	74 0b                	je     41064d <process_udp.isra.0+0x3a8d>
  410642:	48 89 50 20          	mov    %rdx,0x20(%rax)
  410646:	48 8b 93 08 01 00 00 	mov    0x108(%rbx),%rdx
  41064d:	48 85 d2             	test   %rdx,%rdx
  410650:	74 04                	je     410656 <process_udp.isra.0+0x3a96>
  410652:	48 89 42 18          	mov    %rax,0x18(%rdx)
  410656:	83 69 10 01          	subl   $0x1,0x10(%rcx)
  41065a:	48 89 df             	mov    %rbx,%rdi
  41065d:	e8 7e 1e ff ff       	call   4024e0 <free@plt>
  410662:	e9 38 c7 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  410667:	e8 94 42 ff ff       	call   404900 <macaddr_str>
  41066c:	ba c5 09 00 00       	mov    $0x9c5,%edx
  410671:	bf 04 00 00 00       	mov    $0x4,%edi
  410676:	48 8d 0d eb 2e 01 00 	lea    0x12eeb(%rip),%rcx        # 423568 <_IO_stdin_used+0x2568>
  41067d:	49 89 c0             	mov    %rax,%r8
  410680:	48 8d 35 6e 42 01 00 	lea    0x1426e(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  410687:	31 c0                	xor    %eax,%eax
  410689:	e8 e2 3c ff ff       	call   404370 <_traceEvent>
  41068e:	48 8b 85 30 f1 ff ff 	mov    -0xed0(%rbp),%rax
  410695:	66 0f 6f 95 20 f1 ff 	movdqa -0xee0(%rbp),%xmm2
  41069c:	ff 
  41069d:	48 8d 95 60 f1 ff ff 	lea    -0xea0(%rbp),%rdx
  4106a4:	48 8b 8d 50 f0 ff ff 	mov    -0xfb0(%rbp),%rcx
  4106ab:	48 8d b5 f8 f0 ff ff 	lea    -0xf08(%rbp),%rsi
  4106b2:	48 89 85 70 f1 ff ff 	mov    %rax,-0xe90(%rbp)
  4106b9:	48 8d 85 c0 f7 ff ff 	lea    -0x840(%rbp),%rax
  4106c0:	48 89 c7             	mov    %rax,%rdi
  4106c3:	0f 29 95 60 f1 ff ff 	movaps %xmm2,-0xea0(%rbp)
  4106ca:	48 89 85 c0 f0 ff ff 	mov    %rax,-0xf40(%rbp)
  4106d1:	66 83 8d 62 f1 ff ff 	orw    $0x20,-0xe9e(%rbp)
  4106d8:	20 
  4106d9:	e8 b2 aa 00 00       	call   41b190 <encode_QUERY_PEER>
  4106de:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  4106e5:	80 78 16 02          	cmpb   $0x2,0x16(%rax)
  4106e9:	0f 84 c1 06 00 00    	je     410db0 <process_udp.isra.0+0x41f0>
  4106ef:	48 83 ec 08          	sub    $0x8,%rsp
  4106f3:	ff 75 10             	push   0x10(%rbp)
  4106f6:	4c 8b 85 c0 f0 ff ff 	mov    -0xf40(%rbp),%r8
  4106fd:	31 c9                	xor    %ecx,%ecx
  4106ff:	48 8b bd 98 f0 ff ff 	mov    -0xf68(%rbp),%rdi
  410706:	4c 89 fa             	mov    %r15,%rdx
  410709:	31 f6                	xor    %esi,%esi
  41070b:	4c 8b 8d f8 f0 ff ff 	mov    -0xf08(%rbp),%r9
  410712:	e8 b9 8c ff ff       	call   4093d0 <try_broadcast.isra.0>
  410717:	5f                   	pop    %rdi
  410718:	41 58                	pop    %r8
  41071a:	e9 80 c6 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  41071f:	e8 0c 51 ff ff       	call   405830 <time_stamp>
  410724:	48 8b 9d c8 f0 ff ff 	mov    -0xf38(%rbp),%rbx
  41072b:	0f b7 b5 f0 f0 ff ff 	movzwl -0xf10(%rbp),%esi
  410732:	4c 8b b5 c0 f0 ff ff 	mov    -0xf40(%rbp),%r14
  410739:	49 89 c1             	mov    %rax,%r9
  41073c:	48 8b 4b 18          	mov    0x18(%rbx),%rcx
  410740:	4c 8b 43 28          	mov    0x28(%rbx),%r8
  410744:	89 f2                	mov    %esi,%edx
  410746:	4c 89 f7             	mov    %r14,%rdi
  410749:	e8 02 db 00 00       	call   41e250 <packet_header_encrypt>
  41074e:	48 83 7b 58 00       	cmpq   $0x0,0x58(%rbx)
  410753:	0f 84 bd e7 ff ff    	je     40ef16 <process_udp.isra.0+0x2356>
  410759:	48 8b 95 f0 f0 ff ff 	mov    -0xf10(%rbp),%rdx
  410760:	48 8d 9d 80 f2 ff ff 	lea    -0xd80(%rbp),%rbx
  410767:	4c 89 f6             	mov    %r14,%rsi
  41076a:	48 89 df             	mov    %rbx,%rdi
  41076d:	e8 de 5f ff ff       	call   406750 <pearson_hash_128>
  410772:	4c 8b 95 b8 f0 ff ff 	mov    -0xf48(%rbp),%r10
  410779:	48 89 df             	mov    %rbx,%rdi
  41077c:	49 8b 72 40          	mov    0x40(%r10),%rsi
  410780:	e8 1b 8a 00 00       	call   4191a0 <speck_128_encrypt>
  410785:	b9 10 00 00 00       	mov    $0x10,%ecx
  41078a:	48 89 da             	mov    %rbx,%rdx
  41078d:	4c 89 ee             	mov    %r13,%rsi
  410790:	4c 89 f7             	mov    %r14,%rdi
  410793:	e8 48 8c 00 00       	call   4193e0 <encode_buf>
  410798:	e9 79 e7 ff ff       	jmp    40ef16 <process_udp.isra.0+0x2356>
  41079d:	e8 8e 50 ff ff       	call   405830 <time_stamp>
  4107a2:	48 8b 95 f8 f0 ff ff 	mov    -0xf08(%rbp),%rdx
  4107a9:	4c 8b 9d c8 f0 ff ff 	mov    -0xf38(%rbp),%r11
  4107b0:	49 89 c1             	mov    %rax,%r9
  4107b3:	0f b7 c3             	movzwl %bx,%eax
  4107b6:	0f b7 fa             	movzwl %dx,%edi
  4107b9:	48 29 c2             	sub    %rax,%rdx
  4107bc:	b8 10 00 00 00       	mov    $0x10,%eax
  4107c1:	49 8b 4b 20          	mov    0x20(%r11),%rcx
  4107c5:	48 39 c2             	cmp    %rax,%rdx
  4107c8:	4d 8b 43 30          	mov    0x30(%r11),%r8
  4107cc:	48 0f 47 d0          	cmova  %rax,%rdx
  4107d0:	31 c0                	xor    %eax,%eax
  4107d2:	49 83 7b 58 00       	cmpq   $0x0,0x58(%r11)
  4107d7:	0f 45 c2             	cmovne %edx,%eax
  4107da:	89 fa                	mov    %edi,%edx
  4107dc:	4c 89 f7             	mov    %r14,%rdi
  4107df:	89 c6                	mov    %eax,%esi
  4107e1:	01 de                	add    %ebx,%esi
  4107e3:	0f b7 f6             	movzwl %si,%esi
  4107e6:	e8 65 da 00 00       	call   41e250 <packet_header_encrypt>
  4107eb:	e9 f2 dd ff ff       	jmp    40e5e2 <process_udp.isra.0+0x1a22>
  4107f0:	48 8d 0d 91 25 01 00 	lea    0x12591(%rip),%rcx        # 422d88 <_IO_stdin_used+0x1d88>
  4107f7:	ba 33 06 00 00       	mov    $0x633,%edx
  4107fc:	48 8d 35 f2 40 01 00 	lea    0x140f2(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  410803:	31 c0                	xor    %eax,%eax
  410805:	bf 04 00 00 00       	mov    $0x4,%edi
  41080a:	e8 61 3b ff ff       	call   404370 <_traceEvent>
  41080f:	e9 8b c5 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  410814:	e8 17 50 ff ff       	call   405830 <time_stamp>
  410819:	0f b7 b5 f8 f0 ff ff 	movzwl -0xf08(%rbp),%esi
  410820:	48 8b bd c0 f0 ff ff 	mov    -0xf40(%rbp),%rdi
  410827:	49 89 c1             	mov    %rax,%r9
  41082a:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  410831:	89 f2                	mov    %esi,%edx
  410833:	48 8b 48 20          	mov    0x20(%rax),%rcx
  410837:	4c 8b 40 30          	mov    0x30(%rax),%r8
  41083b:	e8 10 da 00 00       	call   41e250 <packet_header_encrypt>
  410840:	e9 a1 e0 ff ff       	jmp    40e8e6 <process_udp.isra.0+0x1d26>
  410845:	48 8b 9d c8 f0 ff ff 	mov    -0xf38(%rbp),%rbx
  41084c:	48 8d 0d c5 25 01 00 	lea    0x125c5(%rip),%rcx        # 422e18 <_IO_stdin_used+0x1e18>
  410853:	ba 47 06 00 00       	mov    $0x647,%edx
  410858:	48 8d 35 96 40 01 00 	lea    0x14096(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  41085f:	bf 03 00 00 00       	mov    $0x3,%edi
  410864:	49 89 d8             	mov    %rbx,%r8
  410867:	e8 04 3b ff ff       	call   404370 <_traceEvent>
  41086c:	66 0f ef c0          	pxor   %xmm0,%xmm0
  410870:	c6 43 16 01          	movb   $0x1,0x16(%rbx)
  410874:	0f 11 43 18          	movups %xmm0,0x18(%rbx)
  410878:	e9 38 e9 ff ff       	jmp    40f1b5 <process_udp.isra.0+0x25f5>
  41087d:	4c 8b 9b f0 00 00 00 	mov    0xf0(%rbx),%r11
  410884:	48 8b 83 f8 00 00 00 	mov    0xf8(%rbx),%rax
  41088b:	4c 8d 8b e8 00 00 00 	lea    0xe8(%rbx),%r9
  410892:	4d 85 db             	test   %r11,%r11
  410895:	74 5c                	je     4108f3 <process_udp.isra.0+0x3d33>
  410897:	4c 01 da             	add    %r11,%rdx
  41089a:	4c 3b 49 18          	cmp    0x18(%rcx),%r9
  41089e:	0f 84 e4 06 00 00    	je     410f88 <process_udp.isra.0+0x43c8>
  4108a4:	48 89 42 10          	mov    %rax,0x10(%rdx)
  4108a8:	48 85 c0             	test   %rax,%rax
  4108ab:	74 10                	je     4108bd <process_udp.isra.0+0x3cfd>
  4108ad:	48 8b 96 e8 00 00 00 	mov    0xe8(%rsi),%rdx
  4108b4:	48 8b 52 20          	mov    0x20(%rdx),%rdx
  4108b8:	4c 89 5c 10 08       	mov    %r11,0x8(%rax,%rdx,1)
  4108bd:	49 8b 88 e8 00 00 00 	mov    0xe8(%r8),%rcx
  4108c4:	48 8b 93 08 01 00 00 	mov    0x108(%rbx),%rdx
  4108cb:	8b 41 08             	mov    0x8(%rcx),%eax
  4108ce:	83 e8 01             	sub    $0x1,%eax
  4108d1:	23 83 1c 01 00 00    	and    0x11c(%rbx),%eax
  4108d7:	48 c1 e0 04          	shl    $0x4,%rax
  4108db:	48 03 01             	add    (%rcx),%rax
  4108de:	83 68 08 01          	subl   $0x1,0x8(%rax)
  4108e2:	4c 3b 08             	cmp    (%rax),%r9
  4108e5:	0f 85 4b fd ff ff    	jne    410636 <process_udp.isra.0+0x3a76>
  4108eb:	48 89 10             	mov    %rdx,(%rax)
  4108ee:	e9 43 fd ff ff       	jmp    410636 <process_udp.isra.0+0x3a76>
  4108f3:	48 85 c0             	test   %rax,%rax
  4108f6:	0f 84 c0 05 00 00    	je     410ebc <process_udp.isra.0+0x42fc>
  4108fc:	4c 3b 49 18          	cmp    0x18(%rcx),%r9
  410900:	0f 84 8b 06 00 00    	je     410f91 <process_udp.isra.0+0x43d1>
  410906:	48 8b b5 c8 f0 ff ff 	mov    -0xf38(%rbp),%rsi
  41090d:	49 89 c0             	mov    %rax,%r8
  410910:	48 89 46 48          	mov    %rax,0x48(%rsi)
  410914:	48 89 c6             	mov    %rax,%rsi
  410917:	eb 94                	jmp    4108ad <process_udp.isra.0+0x3ced>
  410919:	e8 12 4f ff ff       	call   405830 <time_stamp>
  41091e:	4c 8b bd c8 f0 ff ff 	mov    -0xf38(%rbp),%r15
  410925:	0f b7 b5 f8 f0 ff ff 	movzwl -0xf08(%rbp),%esi
  41092c:	4c 8b b5 c0 f0 ff ff 	mov    -0xf40(%rbp),%r14
  410933:	49 89 c1             	mov    %rax,%r9
  410936:	49 8b 4f 18          	mov    0x18(%r15),%rcx
  41093a:	4d 8b 47 28          	mov    0x28(%r15),%r8
  41093e:	89 f2                	mov    %esi,%edx
  410940:	4c 89 f7             	mov    %r14,%rdi
  410943:	e8 08 d9 00 00       	call   41e250 <packet_header_encrypt>
  410948:	49 83 7f 58 00       	cmpq   $0x0,0x58(%r15)
  41094d:	0f 84 c0 d5 ff ff    	je     40df13 <process_udp.isra.0+0x1353>
  410953:	48 8d 95 80 f2 ff ff 	lea    -0xd80(%rbp),%rdx
  41095a:	b9 10 00 00 00       	mov    $0x10,%ecx
  41095f:	48 89 de             	mov    %rbx,%rsi
  410962:	4c 89 f7             	mov    %r14,%rdi
  410965:	e8 76 8a 00 00       	call   4193e0 <encode_buf>
  41096a:	e9 a4 d5 ff ff       	jmp    40df13 <process_udp.isra.0+0x1353>
  41096f:	4c 89 42 18          	mov    %r8,0x18(%rdx)
  410973:	e9 70 fc ff ff       	jmp    4105e8 <process_udp.isra.0+0x3a28>
  410978:	89 95 f8 f0 ff ff    	mov    %edx,-0xf08(%rbp)
  41097e:	48 8d 0d 1b 28 01 00 	lea    0x1281b(%rip),%rcx        # 4231a0 <_IO_stdin_used+0x21a0>
  410985:	ba ee 04 00 00       	mov    $0x4ee,%edx
  41098a:	48 8d 35 64 3f 01 00 	lea    0x13f64(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  410991:	31 c0                	xor    %eax,%eax
  410993:	bf 01 00 00 00       	mov    $0x1,%edi
  410998:	4c 89 95 c0 f0 ff ff 	mov    %r10,-0xf40(%rbp)
  41099f:	e8 cc 39 ff ff       	call   404370 <_traceEvent>
  4109a4:	4c 8b 95 c0 f0 ff ff 	mov    -0xf40(%rbp),%r10
  4109ab:	e9 53 ec ff ff       	jmp    40f603 <process_udp.isra.0+0x2a43>
  4109b0:	e8 7b 4e ff ff       	call   405830 <time_stamp>
  4109b5:	4c 8b b5 c8 f0 ff ff 	mov    -0xf38(%rbp),%r14
  4109bc:	0f b7 b5 f0 f0 ff ff 	movzwl -0xf10(%rbp),%esi
  4109c3:	4c 8b ad c0 f0 ff ff 	mov    -0xf40(%rbp),%r13
  4109ca:	49 89 c1             	mov    %rax,%r9
  4109cd:	49 8b 4e 18          	mov    0x18(%r14),%rcx
  4109d1:	4d 8b 46 28          	mov    0x28(%r14),%r8
  4109d5:	89 f2                	mov    %esi,%edx
  4109d7:	4c 89 ef             	mov    %r13,%rdi
  4109da:	e8 71 d8 00 00       	call   41e250 <packet_header_encrypt>
  4109df:	49 83 7e 58 00       	cmpq   $0x0,0x58(%r14)
  4109e4:	0f 84 eb fa ff ff    	je     4104d5 <process_udp.isra.0+0x3915>
  4109ea:	48 8d 95 80 f2 ff ff 	lea    -0xd80(%rbp),%rdx
  4109f1:	b9 10 00 00 00       	mov    $0x10,%ecx
  4109f6:	48 89 de             	mov    %rbx,%rsi
  4109f9:	4c 89 ef             	mov    %r13,%rdi
  4109fc:	e8 df 89 00 00       	call   4193e0 <encode_buf>
  410a01:	e9 cf fa ff ff       	jmp    4104d5 <process_udp.isra.0+0x3915>
  410a06:	48 8d 0d e3 24 01 00 	lea    0x124e3(%rip),%rcx        # 422ef0 <_IO_stdin_used+0x1ef0>
  410a0d:	ba 8d 06 00 00       	mov    $0x68d,%edx
  410a12:	31 ff                	xor    %edi,%edi
  410a14:	31 c0                	xor    %eax,%eax
  410a16:	48 8d 35 d8 3e 01 00 	lea    0x13ed8(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  410a1d:	e8 4e 39 ff ff       	call   404370 <_traceEvent>
  410a22:	e9 78 c3 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  410a27:	4c 8b bd c8 f0 ff ff 	mov    -0xf38(%rbp),%r15
  410a2e:	66 0f ef c0          	pxor   %xmm0,%xmm0
  410a32:	bf 40 00 00 00       	mov    $0x40,%edi
  410a37:	41 0f 11 47 78       	movups %xmm0,0x78(%r15)
  410a3c:	e8 0f 1d ff ff       	call   402750 <malloc@plt>
  410a41:	49 89 47 70          	mov    %rax,0x70(%r15)
  410a45:	48 89 c3             	mov    %rax,%rbx
  410a48:	48 85 c0             	test   %rax,%rax
  410a4b:	0f 84 53 04 00 00    	je     410ea4 <process_udp.isra.0+0x42e4>
  410a51:	4c 8b bd c8 f0 ff ff 	mov    -0xf38(%rbp),%r15
  410a58:	66 0f ef c0          	pxor   %xmm0,%xmm0
  410a5c:	be 01 00 00 00       	mov    $0x1,%esi
  410a61:	bf 00 02 00 00       	mov    $0x200,%edi
  410a66:	0f 11 40 10          	movups %xmm0,0x10(%rax)
  410a6a:	4d 8d 77 70          	lea    0x70(%r15),%r14
  410a6e:	0f 11 40 20          	movups %xmm0,0x20(%rax)
  410a72:	4c 89 70 18          	mov    %r14,0x18(%rax)
  410a76:	0f 11 40 30          	movups %xmm0,0x30(%rax)
  410a7a:	48 8b 05 57 48 01 00 	mov    0x14857(%rip),%rax        # 4252d8 <null_mac+0x8>
  410a81:	48 c7 43 20 70 00 00 	movq   $0x70,0x20(%rbx)
  410a88:	00 
  410a89:	48 89 43 08          	mov    %rax,0x8(%rbx)
  410a8d:	e8 fe 1b ff ff       	call   402690 <calloc@plt>
  410a92:	c7 43 38 e1 1f 11 a0 	movl   $0xa0111fe1,0x38(%rbx)
  410a99:	48 89 03             	mov    %rax,(%rbx)
  410a9c:	48 85 c0             	test   %rax,%rax
  410a9f:	0f 84 ff 03 00 00    	je     410ea4 <process_udp.isra.0+0x42e4>
  410aa5:	48 8b b5 98 f0 ff ff 	mov    -0xf68(%rbp),%rsi
  410aac:	ba 1f 00 00 00       	mov    $0x1f,%edx
  410ab1:	b9 01 00 00 00       	mov    $0x1,%ecx
  410ab6:	4c 89 be b0 00 00 00 	mov    %r15,0xb0(%rsi)
  410abd:	e9 07 f9 ff ff       	jmp    4103c9 <process_udp.isra.0+0x3809>
  410ac2:	45 8b 74 24 08       	mov    0x8(%r12),%r14d
  410ac7:	49 c1 e6 05          	shl    $0x5,%r14
  410acb:	4c 89 f7             	mov    %r14,%rdi
  410ace:	e8 7d 1c ff ff       	call   402750 <malloc@plt>
  410ad3:	48 89 c3             	mov    %rax,%rbx
  410ad6:	48 85 c0             	test   %rax,%rax
  410ad9:	0f 84 c5 03 00 00    	je     410ea4 <process_udp.isra.0+0x42e4>
  410adf:	31 f6                	xor    %esi,%esi
  410ae1:	4c 89 f1             	mov    %r14,%rcx
  410ae4:	4c 89 f2             	mov    %r14,%rdx
  410ae7:	48 89 c7             	mov    %rax,%rdi
  410aea:	e8 91 1d ff ff       	call   402880 <__memset_chk@plt>
  410aef:	41 8b 44 24 10       	mov    0x10(%r12),%eax
  410af4:	41 8b 74 24 0c       	mov    0xc(%r12),%esi
  410af9:	41 c7 44 24 2c 00 00 	movl   $0x0,0x2c(%r12)
  410b00:	00 00 
  410b02:	41 8b 54 24 08       	mov    0x8(%r12),%edx
  410b07:	49 8b 3c 24          	mov    (%r12),%rdi
  410b0b:	8d 4e 01             	lea    0x1(%rsi),%ecx
  410b0e:	89 c6                	mov    %eax,%esi
  410b10:	44 8d 5c 12 ff       	lea    -0x1(%rdx,%rdx,1),%r11d
  410b15:	d3 ee                	shr    %cl,%esi
  410b17:	44 21 d8             	and    %r11d,%eax
  410b1a:	89 f1                	mov    %esi,%ecx
  410b1c:	83 f8 01             	cmp    $0x1,%eax
  410b1f:	83 d9 ff             	sbb    $0xffffffff,%ecx
  410b22:	41 89 4c 24 28       	mov    %ecx,0x28(%r12)
  410b27:	41 89 c9             	mov    %ecx,%r9d
  410b2a:	85 d2                	test   %edx,%edx
  410b2c:	74 7c                	je     410baa <process_udp.isra.0+0x3fea>
  410b2e:	48 c1 e2 04          	shl    $0x4,%rdx
  410b32:	48 89 f8             	mov    %rdi,%rax
  410b35:	48 01 fa             	add    %rdi,%rdx
  410b38:	4c 8b 10             	mov    (%rax),%r10
  410b3b:	4d 85 d2             	test   %r10,%r10
  410b3e:	74 61                	je     410ba1 <process_udp.isra.0+0x3fe1>
  410b40:	4d 89 d0             	mov    %r10,%r8
  410b43:	44 89 d9             	mov    %r11d,%ecx
  410b46:	4d 8b 52 20          	mov    0x20(%r10),%r10
  410b4a:	41 23 48 34          	and    0x34(%r8),%ecx
  410b4e:	48 c1 e1 04          	shl    $0x4,%rcx
  410b52:	48 01 d9             	add    %rbx,%rcx
  410b55:	8b 71 08             	mov    0x8(%rcx),%esi
  410b58:	83 c6 01             	add    $0x1,%esi
  410b5b:	89 71 08             	mov    %esi,0x8(%rcx)
  410b5e:	41 39 f1             	cmp    %esi,%r9d
  410b61:	73 1e                	jae    410b81 <process_udp.isra.0+0x3fc1>
  410b63:	44 8b 69 0c          	mov    0xc(%rcx),%r13d
  410b67:	45 89 ce             	mov    %r9d,%r14d
  410b6a:	41 83 44 24 2c 01    	addl   $0x1,0x2c(%r12)
  410b70:	45 0f af f5          	imul   %r13d,%r14d
  410b74:	41 39 f6             	cmp    %esi,%r14d
  410b77:	73 08                	jae    410b81 <process_udp.isra.0+0x3fc1>
  410b79:	41 83 c5 01          	add    $0x1,%r13d
  410b7d:	44 89 69 0c          	mov    %r13d,0xc(%rcx)
  410b81:	48 8b 31             	mov    (%rcx),%rsi
  410b84:	49 c7 40 18 00 00 00 	movq   $0x0,0x18(%r8)
  410b8b:	00 
  410b8c:	49 89 70 20          	mov    %rsi,0x20(%r8)
  410b90:	48 85 f6             	test   %rsi,%rsi
  410b93:	74 04                	je     410b99 <process_udp.isra.0+0x3fd9>
  410b95:	4c 89 46 18          	mov    %r8,0x18(%rsi)
  410b99:	4c 89 01             	mov    %r8,(%rcx)
  410b9c:	4d 85 d2             	test   %r10,%r10
  410b9f:	75 9f                	jne    410b40 <process_udp.isra.0+0x3f80>
  410ba1:	48 83 c0 10          	add    $0x10,%rax
  410ba5:	48 39 d0             	cmp    %rdx,%rax
  410ba8:	75 8e                	jne    410b38 <process_udp.isra.0+0x3f78>
  410baa:	e8 31 19 ff ff       	call   4024e0 <free@plt>
  410baf:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  410bb6:	48 8b 40 70          	mov    0x70(%rax),%rax
  410bba:	8b 50 10             	mov    0x10(%rax),%edx
  410bbd:	83 40 0c 01          	addl   $0x1,0xc(%rax)
  410bc1:	48 89 18             	mov    %rbx,(%rax)
  410bc4:	d1 60 08             	shll   $1,0x8(%rax)
  410bc7:	d1 ea                	shr    $1,%edx
  410bc9:	3b 50 2c             	cmp    0x2c(%rax),%edx
  410bcc:	0f 82 0f 02 00 00    	jb     410de1 <process_udp.isra.0+0x4221>
  410bd2:	c7 40 30 00 00 00 00 	movl   $0x0,0x30(%rax)
  410bd9:	e9 4e f8 ff ff       	jmp    41042c <process_udp.isra.0+0x386c>
  410bde:	41 89 c0             	mov    %eax,%r8d
  410be1:	4c 89 e7             	mov    %r12,%rdi
  410be4:	b8 ef be ed fe       	mov    $0xfeedbeef,%eax
  410be9:	ba b9 79 37 9e       	mov    $0x9e3779b9,%edx
  410bee:	b9 b9 79 37 9e       	mov    $0x9e3779b9,%ecx
  410bf3:	e9 3d c3 ff ff       	jmp    40cf35 <process_udp.isra.0+0x375>
  410bf8:	48 85 c0             	test   %rax,%rax
  410bfb:	0f 84 b8 02 00 00    	je     410eb9 <process_udp.isra.0+0x42f9>
  410c01:	48 3b 72 18          	cmp    0x18(%rdx),%rsi
  410c05:	0f 84 a1 02 00 00    	je     410eac <process_udp.isra.0+0x42ec>
  410c0b:	48 8b 8d c8 f0 ff ff 	mov    -0xf38(%rbp),%rcx
  410c12:	48 89 41 48          	mov    %rax,0x48(%rcx)
  410c16:	48 89 c1             	mov    %rax,%rcx
  410c19:	e9 da f9 ff ff       	jmp    4105f8 <process_udp.isra.0+0x3a38>
  410c1e:	48 89 10             	mov    %rdx,(%rax)
  410c21:	e9 b6 f4 ff ff       	jmp    4100dc <process_udp.isra.0+0x351c>
  410c26:	4c 89 42 18          	mov    %r8,0x18(%rdx)
  410c2a:	e9 5b f4 ff ff       	jmp    41008a <process_udp.isra.0+0x34ca>
  410c2f:	48 85 c0             	test   %rax,%rax
  410c32:	0f 84 3e 04 00 00    	je     411076 <process_udp.isra.0+0x44b6>
  410c38:	48 3b 72 18          	cmp    0x18(%rdx),%rsi
  410c3c:	0f 84 27 04 00 00    	je     411069 <process_udp.isra.0+0x44a9>
  410c42:	48 8b 8d c8 f0 ff ff 	mov    -0xf38(%rbp),%rcx
  410c49:	48 89 41 48          	mov    %rax,0x48(%rcx)
  410c4d:	48 89 c1             	mov    %rax,%rcx
  410c50:	e9 46 f4 ff ff       	jmp    41009b <process_udp.isra.0+0x34db>
  410c55:	48 8d 0d 84 26 01 00 	lea    0x12684(%rip),%rcx        # 4232e0 <_IO_stdin_used+0x22e0>
  410c5c:	ba bd 08 00 00       	mov    $0x8bd,%edx
  410c61:	48 8d 35 8d 3c 01 00 	lea    0x13c8d(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  410c68:	31 c0                	xor    %eax,%eax
  410c6a:	bf 04 00 00 00       	mov    $0x4,%edi
  410c6f:	e8 fc 36 ff ff       	call   404370 <_traceEvent>
  410c74:	e9 26 c1 ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  410c79:	48 8d 0d 82 3e 01 00 	lea    0x13e82(%rip),%rcx        # 424b02 <_IO_stdin_used+0x3b02>
  410c80:	ba 40 08 00 00       	mov    $0x840,%edx
  410c85:	48 8d 35 69 3c 01 00 	lea    0x13c69(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  410c8c:	31 c0                	xor    %eax,%eax
  410c8e:	bf 04 00 00 00       	mov    $0x4,%edi
  410c93:	4c 89 95 b8 f0 ff ff 	mov    %r10,-0xf48(%rbp)
  410c9a:	e8 d1 36 ff ff       	call   404370 <_traceEvent>
  410c9f:	4c 8b b5 98 f0 ff ff 	mov    -0xf68(%rbp),%r14
  410ca6:	4c 89 f7             	mov    %r14,%rdi
  410ca9:	e8 62 91 ff ff       	call   409e10 <send_re_register_super>
  410cae:	8b 85 7c f2 ff ff    	mov    -0xd84(%rbp),%eax
  410cb4:	4c 89 f7             	mov    %r14,%rdi
  410cb7:	41 89 86 1c 01 00 00 	mov    %eax,0x11c(%r14)
  410cbe:	e8 6d 90 ff ff       	call   409d30 <calculate_dynamic_keys>
  410cc3:	49 8b b6 c0 00 00 00 	mov    0xc0(%r14),%rsi
  410cca:	48 8b 55 10          	mov    0x10(%rbp),%rdx
  410cce:	4c 89 f7             	mov    %r14,%rdi
  410cd1:	b9 01 00 00 00       	mov    $0x1,%ecx
  410cd6:	e8 95 84 ff ff       	call   409170 <re_register_and_purge_supernodes.part.0>
  410cdb:	41 8b 86 1c 01 00 00 	mov    0x11c(%r14),%eax
  410ce2:	4c 8b 95 b8 f0 ff ff 	mov    -0xf48(%rbp),%r10
  410ce9:	e9 65 f1 ff ff       	jmp    40fe53 <process_udp.isra.0+0x3293>
  410cee:	e8 3d 4b ff ff       	call   405830 <time_stamp>
  410cf3:	0f b7 b5 f8 f0 ff ff 	movzwl -0xf08(%rbp),%esi
  410cfa:	48 8b bd c0 f0 ff ff 	mov    -0xf40(%rbp),%rdi
  410d01:	49 89 c1             	mov    %rax,%r9
  410d04:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  410d0b:	89 f2                	mov    %esi,%edx
  410d0d:	48 8b 48 20          	mov    0x20(%rax),%rcx
  410d11:	4c 8b 40 30          	mov    0x30(%rax),%r8
  410d15:	e8 36 d5 00 00       	call   41e250 <packet_header_encrypt>
  410d1a:	e9 ea c6 ff ff       	jmp    40d409 <process_udp.isra.0+0x849>
  410d1f:	e8 0c 4b ff ff       	call   405830 <time_stamp>
  410d24:	4c 8b b5 c8 f0 ff ff 	mov    -0xf38(%rbp),%r14
  410d2b:	0f b7 b5 f0 f0 ff ff 	movzwl -0xf10(%rbp),%esi
  410d32:	48 8b bd c0 f0 ff ff 	mov    -0xf40(%rbp),%rdi
  410d39:	49 89 c1             	mov    %rax,%r9
  410d3c:	49 8b 4e 18          	mov    0x18(%r14),%rcx
  410d40:	4d 8b 46 28          	mov    0x28(%r14),%r8
  410d44:	89 f2                	mov    %esi,%edx
  410d46:	e8 05 d5 00 00       	call   41e250 <packet_header_encrypt>
  410d4b:	49 83 7e 58 00       	cmpq   $0x0,0x58(%r14)
  410d50:	4c 8b 95 b8 f0 ff ff 	mov    -0xf48(%rbp),%r10
  410d57:	0f 84 92 f4 ff ff    	je     4101ef <process_udp.isra.0+0x362f>
  410d5d:	48 8b 95 f0 f0 ff ff 	mov    -0xf10(%rbp),%rdx
  410d64:	4c 8d b5 80 f2 ff ff 	lea    -0xd80(%rbp),%r14
  410d6b:	48 8b b5 c0 f0 ff ff 	mov    -0xf40(%rbp),%rsi
  410d72:	4c 89 f7             	mov    %r14,%rdi
  410d75:	e8 d6 59 ff ff       	call   406750 <pearson_hash_128>
  410d7a:	4c 8b 95 b8 f0 ff ff 	mov    -0xf48(%rbp),%r10
  410d81:	4c 89 f7             	mov    %r14,%rdi
  410d84:	49 8b 72 40          	mov    0x40(%r10),%rsi
  410d88:	e8 13 84 00 00       	call   4191a0 <speck_128_encrypt>
  410d8d:	b9 10 00 00 00       	mov    $0x10,%ecx
  410d92:	4c 89 f2             	mov    %r14,%rdx
  410d95:	4c 89 ee             	mov    %r13,%rsi
  410d98:	48 8b bd c0 f0 ff ff 	mov    -0xf40(%rbp),%rdi
  410d9f:	e8 3c 86 00 00       	call   4193e0 <encode_buf>
  410da4:	4c 8b 95 b8 f0 ff ff 	mov    -0xf48(%rbp),%r10
  410dab:	e9 3f f4 ff ff       	jmp    4101ef <process_udp.isra.0+0x362f>
  410db0:	e8 7b 4a ff ff       	call   405830 <time_stamp>
  410db5:	0f b7 b5 f8 f0 ff ff 	movzwl -0xf08(%rbp),%esi
  410dbc:	48 8b bd c0 f0 ff ff 	mov    -0xf40(%rbp),%rdi
  410dc3:	49 89 c1             	mov    %rax,%r9
  410dc6:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  410dcd:	89 f2                	mov    %esi,%edx
  410dcf:	48 8b 48 20          	mov    0x20(%rax),%rcx
  410dd3:	4c 8b 40 30          	mov    0x30(%rax),%r8
  410dd7:	e8 74 d4 00 00       	call   41e250 <packet_header_encrypt>
  410ddc:	e9 0e f9 ff ff       	jmp    4106ef <process_udp.isra.0+0x3b2f>
  410de1:	8b 70 30             	mov    0x30(%rax),%esi
  410de4:	8d 56 01             	lea    0x1(%rsi),%edx
  410de7:	89 50 30             	mov    %edx,0x30(%rax)
  410dea:	83 fa 01             	cmp    $0x1,%edx
  410ded:	0f 86 39 f6 ff ff    	jbe    41042c <process_udp.isra.0+0x386c>
  410df3:	c7 40 34 01 00 00 00 	movl   $0x1,0x34(%rax)
  410dfa:	e9 2d f6 ff ff       	jmp    41042c <process_udp.isra.0+0x386c>
  410dff:	4c 8d 85 24 f1 ff ff 	lea    -0xedc(%rbp),%r8
  410e06:	48 8d 0d e3 23 01 00 	lea    0x123e3(%rip),%rcx        # 4231f0 <_IO_stdin_used+0x21f0>
  410e0d:	31 c0                	xor    %eax,%eax
  410e0f:	ba 85 08 00 00       	mov    $0x885,%edx
  410e14:	48 8d 35 da 3a 01 00 	lea    0x13ada(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  410e1b:	bf 04 00 00 00       	mov    $0x4,%edi
  410e20:	e8 4b 35 ff ff       	call   404370 <_traceEvent>
  410e25:	e9 75 bf ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  410e2a:	4c 8d 85 24 f1 ff ff 	lea    -0xedc(%rbp),%r8
  410e31:	48 8d 0d 50 21 01 00 	lea    0x12150(%rip),%rcx        # 422f88 <_IO_stdin_used+0x1f88>
  410e38:	31 c0                	xor    %eax,%eax
  410e3a:	ba c1 06 00 00       	mov    $0x6c1,%edx
  410e3f:	48 8d 35 af 3a 01 00 	lea    0x13aaf(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  410e46:	bf 04 00 00 00       	mov    $0x4,%edi
  410e4b:	e8 20 35 ff ff       	call   404370 <_traceEvent>
  410e50:	e9 4a bf ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  410e55:	4c 8d 85 24 f1 ff ff 	lea    -0xedc(%rbp),%r8
  410e5c:	48 8d 0d 95 26 01 00 	lea    0x12695(%rip),%rcx        # 4234f8 <_IO_stdin_used+0x24f8>
  410e63:	31 c0                	xor    %eax,%eax
  410e65:	ba 9e 09 00 00       	mov    $0x99e,%edx
  410e6a:	48 8d 35 84 3a 01 00 	lea    0x13a84(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  410e71:	bf 04 00 00 00       	mov    $0x4,%edi
  410e76:	e8 f5 34 ff ff       	call   404370 <_traceEvent>
  410e7b:	e9 1f bf ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  410e80:	48 8d 0d 89 20 01 00 	lea    0x12089(%rip),%rcx        # 422f10 <_IO_stdin_used+0x1f10>
  410e87:	ba 9b 06 00 00       	mov    $0x69b,%edx
  410e8c:	48 8d 35 62 3a 01 00 	lea    0x13a62(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  410e93:	31 c0                	xor    %eax,%eax
  410e95:	bf 01 00 00 00       	mov    $0x1,%edi
  410e9a:	e8 d1 34 ff ff       	call   404370 <_traceEvent>
  410e9f:	e9 fb be ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  410ea4:	83 cf ff             	or     $0xffffffff,%edi
  410ea7:	e8 e4 19 ff ff       	call   402890 <exit@plt>
  410eac:	48 8b 4a 20          	mov    0x20(%rdx),%rcx
  410eb0:	48 89 4a 18          	mov    %rcx,0x18(%rdx)
  410eb4:	e9 52 fd ff ff       	jmp    410c0b <process_udp.isra.0+0x404b>
  410eb9:	48 8b 3a             	mov    (%rdx),%rdi
  410ebc:	e8 1f 16 ff ff       	call   4024e0 <free@plt>
  410ec1:	4c 8b bd c8 f0 ff ff 	mov    -0xf38(%rbp),%r15
  410ec8:	49 8b 47 48          	mov    0x48(%r15),%rax
  410ecc:	48 8b b8 e8 00 00 00 	mov    0xe8(%rax),%rdi
  410ed3:	e8 08 16 ff ff       	call   4024e0 <free@plt>
  410ed8:	31 c0                	xor    %eax,%eax
  410eda:	49 89 47 48          	mov    %rax,0x48(%r15)
  410ede:	e9 77 f7 ff ff       	jmp    41065a <process_udp.isra.0+0x3a9a>
  410ee3:	4c 8d 85 24 f1 ff ff 	lea    -0xedc(%rbp),%r8
  410eea:	48 8d 0d bf 26 01 00 	lea    0x126bf(%rip),%rcx        # 4235b0 <_IO_stdin_used+0x25b0>
  410ef1:	31 c0                	xor    %eax,%eax
  410ef3:	ba e1 09 00 00       	mov    $0x9e1,%edx
  410ef8:	48 8d 35 f6 39 01 00 	lea    0x139f6(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  410eff:	bf 04 00 00 00       	mov    $0x4,%edi
  410f04:	e8 67 34 ff ff       	call   404370 <_traceEvent>
  410f09:	e9 91 be ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  410f0e:	4c 8d 85 24 f1 ff ff 	lea    -0xedc(%rbp),%r8
  410f15:	48 8d 0d bc 20 01 00 	lea    0x120bc(%rip),%rcx        # 422fd8 <_IO_stdin_used+0x1fd8>
  410f1c:	31 c0                	xor    %eax,%eax
  410f1e:	ba 14 07 00 00       	mov    $0x714,%edx
  410f23:	48 8d 35 cb 39 01 00 	lea    0x139cb(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  410f2a:	bf 04 00 00 00       	mov    $0x4,%edi
  410f2f:	e8 3c 34 ff ff       	call   404370 <_traceEvent>
  410f34:	e9 66 be ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  410f39:	e8 f2 48 ff ff       	call   405830 <time_stamp>
  410f3e:	0f b7 b5 f8 f0 ff ff 	movzwl -0xf08(%rbp),%esi
  410f45:	48 8b bd c0 f0 ff ff 	mov    -0xf40(%rbp),%rdi
  410f4c:	49 89 c1             	mov    %rax,%r9
  410f4f:	48 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%rax
  410f56:	89 f2                	mov    %esi,%edx
  410f58:	48 8b 48 20          	mov    0x20(%rax),%rcx
  410f5c:	4c 8b 40 30          	mov    0x30(%rax),%r8
  410f60:	e8 eb d2 00 00       	call   41e250 <packet_header_encrypt>
  410f65:	e9 5c c7 ff ff       	jmp    40d6c6 <process_udp.isra.0+0xb06>
  410f6a:	48 8b bd c8 f0 ff ff 	mov    -0xf38(%rbp),%rdi
  410f71:	41 89 c0             	mov    %eax,%r8d
  410f74:	be ef be ed fe       	mov    $0xfeedbeef,%esi
  410f79:	ba b9 79 37 9e       	mov    $0x9e3779b9,%edx
  410f7e:	b9 b9 79 37 9e       	mov    $0x9e3779b9,%ecx
  410f83:	e9 a0 f0 ff ff       	jmp    410028 <process_udp.isra.0+0x3468>
  410f88:	48 89 51 18          	mov    %rdx,0x18(%rcx)
  410f8c:	e9 13 f9 ff ff       	jmp    4108a4 <process_udp.isra.0+0x3ce4>
  410f91:	48 89 51 18          	mov    %rdx,0x18(%rcx)
  410f95:	e9 6c f9 ff ff       	jmp    410906 <process_udp.isra.0+0x3d46>
  410f9a:	e8 21 16 ff ff       	call   4025c0 <__stack_chk_fail@plt>
  410f9f:	4d 89 f0             	mov    %r14,%r8
  410fa2:	ba a2 07 00 00       	mov    $0x7a2,%edx
  410fa7:	bf 03 00 00 00       	mov    $0x3,%edi
  410fac:	31 c0                	xor    %eax,%eax
  410fae:	48 8d 0d 13 21 01 00 	lea    0x12113(%rip),%rcx        # 4230c8 <_IO_stdin_used+0x20c8>
  410fb5:	48 8d 35 39 39 01 00 	lea    0x13939(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  410fbc:	e8 af 33 ff ff       	call   404370 <_traceEvent>
  410fc1:	e9 d9 bd ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  410fc6:	4c 8d 85 24 f1 ff ff 	lea    -0xedc(%rbp),%r8
  410fcd:	48 8d 0d 34 24 01 00 	lea    0x12434(%rip),%rcx        # 423408 <_IO_stdin_used+0x2408>
  410fd4:	31 c0                	xor    %eax,%eax
  410fd6:	ba 0e 09 00 00       	mov    $0x90e,%edx
  410fdb:	48 8d 35 13 39 01 00 	lea    0x13913(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  410fe2:	bf 04 00 00 00       	mov    $0x4,%edi
  410fe7:	e8 84 33 ff ff       	call   404370 <_traceEvent>
  410fec:	e9 ae bd ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  410ff1:	48 8d 0d 30 22 01 00 	lea    0x12230(%rip),%rcx        # 423228 <_IO_stdin_used+0x2228>
  410ff8:	ba 8a 08 00 00       	mov    $0x88a,%edx
  410ffd:	48 8d 35 f1 38 01 00 	lea    0x138f1(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  411004:	31 c0                	xor    %eax,%eax
  411006:	bf 04 00 00 00       	mov    $0x4,%edi
  41100b:	e8 60 33 ff ff       	call   404370 <_traceEvent>
  411010:	e9 8a bd ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  411015:	4c 8b 85 c8 f0 ff ff 	mov    -0xf38(%rbp),%r8
  41101c:	48 8d 0d 8d 1d 01 00 	lea    0x11d8d(%rip),%rcx        # 422db0 <_IO_stdin_used+0x1db0>
  411023:	31 c0                	xor    %eax,%eax
  411025:	ba 41 06 00 00       	mov    $0x641,%edx
  41102a:	48 8d 35 c4 38 01 00 	lea    0x138c4(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  411031:	bf 04 00 00 00       	mov    $0x4,%edi
  411036:	e8 35 33 ff ff       	call   404370 <_traceEvent>
  41103b:	e9 5f bd ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  411040:	4c 8d 85 24 f1 ff ff 	lea    -0xedc(%rbp),%r8
  411047:	48 8d 0d 62 22 01 00 	lea    0x12262(%rip),%rcx        # 4232b0 <_IO_stdin_used+0x22b0>
  41104e:	ba b8 08 00 00       	mov    $0x8b8,%edx
  411053:	bf 04 00 00 00       	mov    $0x4,%edi
  411058:	48 8d 35 96 38 01 00 	lea    0x13896(%rip),%rsi        # 4248f5 <_IO_stdin_used+0x38f5>
  41105f:	e8 0c 33 ff ff       	call   404370 <_traceEvent>
  411064:	e9 36 bd ff ff       	jmp    40cd9f <process_udp.isra.0+0x1df>
  411069:	48 8b 4a 20          	mov    0x20(%rdx),%rcx
  41106d:	48 89 4a 18          	mov    %rcx,0x18(%rdx)
  411071:	e9 cc fb ff ff       	jmp    410c42 <process_udp.isra.0+0x4082>
  411076:	48 8b 3a             	mov    (%rdx),%rdi
  411079:	45 31 ed             	xor    %r13d,%r13d
  41107c:	e8 5f 14 ff ff       	call   4024e0 <free@plt>
  411081:	48 8b 9d c8 f0 ff ff 	mov    -0xf38(%rbp),%rbx
  411088:	48 8b 43 48          	mov    0x48(%rbx),%rax
  41108c:	48 8b b8 e8 00 00 00 	mov    0xe8(%rax),%rdi
  411093:	e8 48 14 ff ff       	call   4024e0 <free@plt>
  411098:	4c 89 6b 48          	mov    %r13,0x48(%rbx)
  41109c:	e9 61 f0 ff ff       	jmp    410102 <process_udp.isra.0+0x3542>
