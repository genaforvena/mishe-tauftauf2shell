# Exposure probe 2: instrument every case-conversion C call during a
# hostile request cycle and log receiver encoding + content. Loopback
# only (127.0.0.1).
require 'sinatra'
set :bind, '127.0.0.1'
set :port, 4545

TRACE = File.open('/tmp/case-trace.log', 'a'); TRACE.sync = true
tp = TracePoint.new(:c_call) do |t|
  begin
    m = t.method_id.to_s
    if %w[upcase downcase swapcase casecmp casecmp?].include?(m) ||
       m.start_with?('rb_str_upcase')
      recv = t.self
      if recv.is_a?(String)
        TRACE.write("#{m}\tenc=#{recv.encoding.name}\tbs=#{recv.bytesize}\thex=#{recv.b[0,24].unpack1('H*') rescue '?'}\n")
      end
    end
  rescue
  end
end
tp.enable

before do
  TRACE.write("== req #{request.request_method} #{request.path_info}\n")
end

post '/case' do
  q = params['q']
  "q.enc=#{q ? q.encoding.name : 'nil'}\n"
end

get '/case' do
  q = params['q']
  "q.enc=#{q ? q.encoding.name : 'nil'}\n"
end
