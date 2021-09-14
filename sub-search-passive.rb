#!/bin/env ruby


require 'digest'
require 'net/http'
require 'optparse'


VERSION = '(v1.0.1) forked from https://github.com/Madhava-mng/m4dh4v45b1n'
DEPTH = 1
URLS = [
  [
    "https://raw.githubusercontent.com/cyb3r-mafia/subdomains/main/assets/<SDCD>.sdcd",
    "URL",
    "SHA1",
    "SDCD",
    "@",
    ","
  ],
  [
    "https://raw.githubusercontent.com/cyb3r-mafia/subdomains/main/assets2/<SDCD>.sdcd",
    "URL",
    "SHA1",
    "SDCD",
    "@",
    ","
  ],
  [
    "https://raw.githubusercontent.com/cyb3r-mafia/subdomains/main/assets3/<SDCD>.sdcd",
    "URL",
    "SHA1",
    "SDCD",
    "@",
    ","
  ],
  [
    "https://raw.githubusercontent.com/cyb3r-mafia/subdomains/main/assets4/<SDCD>.sdcd",
    "URL",
    "SHA1",
    "SDCD",
    "@",
    ","
  ],
  [
    "https://raw.githubusercontent.com/cyb3r-mafia/subdomains/main/assets5/<SDCD>.sdcd",
    "URL",
    "SHA1",
    "SDCD",
    "@",
    ","
  ],
  [
    "https://raw.githubusercontent.com/cyb3r-mafia/subdomains/main/assets6/<SDCD>.sdcd",
    "URL",
    "SHA1",
    "SDCD",
    "@",
    ","
  ]
]

SORCE_DEPTH = 1
CONFIG_FILE = ENV["HOME"] + "/.s-pasive.conf"

tmp = []
tmp2 = []
src = ''

class FormatError < IOError;end

def rot47(data, iter = 47)
  tmp_value = ''
  data.bytes.map do |c|
    if c > 32 and c < 127
      c += iter
      loop do
        if c > 126
          c = (c - 126)+32
        end
        break if c > 32 and c < 127
      end
    end
    tmp_value += c.chr
  end
  return tmp_value
end

module Sdcd
  class SDCD
    attr_accessor :format,:domain
    def initialize
    end

    def compress(domain, list_subdomain)
      @format = "\x01\xEE5&%&\xEE\xED\x03#{domain.strip}\xFA"
      list_subdomain.map {|e| e.strip}.uniq.map do |s|
        s = s.sub(".#{domain.strip}", "")
        if s != ""
          s+= "\xFA"
          @format += s
        end
      end
      return rot47(@format, 30)
    end

    def decompress(data, tmp = [])
      data = rot47(data, 64).dump
      data = data[1,data.length-2]
      data = data.split('\xFA')
      header = data[0]
      if(header[0,24] == '\x01\xEE5&%&\xEE\xED\x03')
        domain = header.split('\x03')[1]
        subdomain = data[1,data.length-1]
        subdomain.map do |s|
          tmp.append("#{s}.#{domain}")
        end
        result = {}
        result[domain] = tmp
        return result
      else
        raise FormatError::new("Unknown SDCD data")
      end
    end

    def write(file, domain, list_subdomain)
      File.open(file, 'w') do |f|
        return f.write(compress(domain, list_subdomain))
      end
    end

    def read(file)
      File.open(file, 'rb') do |f|
        return decompress(f.read)
      end
    end

  end
end

include Sdcd

if !File.exist? CONFIG_FILE
  File.open(CONFIG_FILE, "w") do |f|
    puts "File created: #{CONFIG_FILE}"
    f.write("# URL   TYPE      HASH/TEXT     FORMAT       DATA     SPLIT\n")
    f.write("# Not tabs or two space. only one space seperation.\n")
    f.write("# <SDCD> is the file replacer\n")
    f.write("# /path/to/sdcds/<SDCD>.sdcd DIR SHA1 SDCD @ ,\n")
    URLS.map do |url|
      f.write(url.join(" ")+"\n")
    end
  end
end

if File.exist? CONFIG_FILE
  File.open(CONFIG_FILE, "r") do |f|
    f.readlines.map do |l|
      if !l.start_with? "#"
        val  = l.chop.split(" ")
        if val[1] == "URL"
          tmp.append(val)
          src += "\e[34;1m🌐 #{val[0]}\e[0m\n"
        elsif val[1] == "DIR"
          src +=  "\e[34;1m  #{val[0]}\e[0m\n"
          tmp2.append(val)
        else
          src += "\e[31;1m✘ #{l}\e[0m\n"
        end
      end
    end
  end
else
  puts "Need environment variable 'HOME'."
end

SDCD_URL_DIR = tmp
SDCD_DIR = tmp2
SRC = src

class ReconSubdomain

  attr_accessor :domain,:depth,:sdcd_dir,:sdcd_url_dir,:source_depth,:out,:notin,:max_res

  def initialize 
    @depth = DEPTH
    @sdcd_url_dir = SDCD_URL_DIR
    @source_depth = SORCE_DEPTH
    @sdcd_dir = SDCD_DIR
    @notin = []
    @max_res = 500
  end

  def hashit(type, data)
    case type
    when "SHA1"
      return Digest::SHA1::new.hexdigest(data)
    when "MD5"
      return Digest::MD5::new.hexdigest(data)
    end
    return data
  end

  def local_file
    hash = @domain
    @sdcd_dir.map do |templet|
      if @source_depth != 0
        if templet[-3] == "SDCD" and templet[1] == "DIR"
          hash = hashit(templet[-4], @domain)
          @depth.times do |d|
            if d > 0
              hash = hashit(templet[-4], @domain + d.to_s)
            end
            path = templet[0].gsub("<SDCD>", hash)
            if File.exist? path
              puts "\n\e[32m[+] Data Found at depth\e[0m #{d}.\n\n"
              sdcd_dict = SDCD::new.read(path)
              sdcd_dict[@domain].map do |us_data|
                ips,sdomain = us_data.split(templet[-2])
                if !@notin.include? sdomain
                  @notin.append(sdomain)
                  puts "[\e[32;1m+\e[0m] \e[36;1m#{sdomain}\e[0m  |\e[2;1m#{ips.gsub(templet[-1],"\e[0m|\e[2;1m")}\e[0m|"
                  if !@out.nil?
                    File.open(@out, "a") do |l|
                      l.write(sdomain + "\n")
                    end
                  end
                end
                if @max_res == @notin.length
                  exit
                end
              end
              @source_depth -= 1
            end
          end
        end
      end
    end
  end

  def scan
    hash = @domain

    local_file

    @sdcd_url_dir.map do |templet|
      if @source_depth != 0
        # Check to Use sdcd
        if templet[-3] == "SDCD" and templet[1] == "URL"
          hash = hashit(templet[-4], @domain)

          @depth.times do |d|
            if d > 0
              hash = hashit(templet[-4], @domain + d.to_s)
            end
            url = templet[0].gsub("<SDCD>", hash)
            req = Net::HTTP::get_response(URI url)
            if req.code == '200'
              puts "\n\e[32m[+] Data Found at depth\e[0m #{d}.\n\n"
              sdcd_dict = SDCD::new.decompress(req.body)
              sdcd_dict[@domain].map do |us_data|
                ips,sdomain = us_data.split(templet[-2])
                if !@notin.include? sdomain
                  @notin.append(sdomain)
                  puts "[\e[32;1m+\e[0m] \e[36;1m#{sdomain}\e[0m  |\e[2;1m#{ips.gsub(templet[-1],"\e[0m|\e[2;1m")}\e[0m|"
                  if !@out.nil?
                    File.open(@out, "a") do |l|
                      l.write(sdomain + "\n")
                    end
                  end
                end
                if @max_res == @notin.length
                  exit
                end
              end
              @source_depth -= 1
            else
              break
            end
          end
        end
      end
    end
  end
end



def main
  init = ReconSubdomain::new
  OptParse::new do |optp|
    optp.program_name = "recon-passive-subdomain"
    optp.summary_width = 24
    optp.version = VERSION
    optp.banner = "Usage: recon-passive-subdomain.rb [ARG] DOMAIN\n
des: Passive recon for subdomains. data collected
from sdcd files. with out intract target or dns.
Edit the ~/.s-passive.conf for more customize.
licensed under GNU.You can modify If you 
willing to read my code. :) (m4dh4v45b1n)\n\n"
    optp.on('-o', '--out [FILE]','Put the domains to file') do |o|
      init.out = o
    end
    optp.on('-d', '--depth [INT]', Integer,"Incress If you need more result. default is #{DEPTH}.") do |d|
      init.depth = d
    end
    optp.on('-s', '--source-depth [INT]', Integer,"Print only from n number of source. default is #{SORCE_DEPTH}.") do |d|
      init.source_depth = d
    end
    optp.on('-m', '--max-result [INT]', Integer,'Print only n number of result. default is 500.') do |d|
      init.max_res = d
    end
    optp.on('-h', '--help', 'Print this banner and exit') do |h|
      puts optp
      exit
    end
  end.parse!
  if init.domain.nil?
    init.domain = ARGV[-1]
  end
  if !init.domain.nil?
    puts SRC
    init.scan
  else
    puts "Usage: recon-passive-subdomain.rb [ARG] DOMAIN\n use --help for more info."
  end
end

main
