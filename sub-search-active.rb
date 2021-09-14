#!/bin/env ruby

require 'optparse'
require 'resolv'
require 'net/http'
require 'resolv-replace'

VERSION = "(v0.0.1) forked from https://github.com/Madhava-mng/m4dh4v45b1n"

USER_AGENTS = [
  "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 OPR/77.0.4054.90",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
  "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Vivaldi/4.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Vivaldi/4.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
  "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9",
  "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36",
  "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1",
  "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36 Vivaldi/4.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36 Vivaldi/4.0"
]

NAME_SERVERS = {
  "Cloudflare": ['1.1.1.1', '1.0.0.1'],
  "Google": ['8.8.8.8', '8.8.4.4'],
  "Quad9": ['9.9.9.9', '149.112.112.112'],
  "OpenDns": ['208.67.222.222', '208.67.220.222']
}

TIME_OUT = 1
MAX_THREAD = 25

def wordlist
  if File.exist? "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt"
    return "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt"
  elsif File.exist? "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
    return "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
  elsif File.exist? "/opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt"
    return "opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt"
  elsif File.exist? "/opt/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
    return "opt/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
  elsif File.exist? "/opt/seclist/Discovery/DNS/subdomains-top1million-110000.txt"
    return "/opt/seclist/Discovery/DNS/subdomains-top1million-110000.txt"
  end
end

def cache_subdomain
  if !ENV["HOME"].nil?
    if !File.exist? ENV["HOME"]+"/.cache"
      Dir::mkdir ENV["HOME"]+"/.cache"
    end
    if !File.exist? ENV["HOME"]+"/.cache/enum-subdomain"
      Dir::mkdir ENV["HOME"]+"/.cache/enum-subdomain"
    end
    if File.exist? ENV["HOME"]+"/.cache/enum-subdomain"
      return ENV["HOME"]+"/.cache/enum-subdomain"
    end
  end
  return nil
end

CACHE = cache_subdomain
WORDLIST = wordlist

class Subdomain_enum
  attr_accessor :target, :wordlist, :timeout, :max_thread, :out, :verbose,:cache_file,:show_cache, :show_cache_without_d,:show_new
  def initialize
    @timeout = TIME_OUT
    @max_thread = MAX_THREAD
    @wordlist = WORDLIST
    @verbose = false
    @outb=""
    @show_cache = false
    @show_new = true
    @show_cache_without_d = true
  end
  def loader(list)
    return Resolv::DefaultResolver.replace_resolvers([
      Resolv::Hosts.new,
      Resolv::DNS.new(
        nameserver: list,
        ndots: 1
      )
    ])
  end
  def get_domain(domain)
    NAME_SERVERS.keys.shuffle.map do |dns|
      begin
        Timeout::timeout(@timeout) do
          addrs = Resolv::new(
            loader(NAME_SERVERS[dns])
          ).getaddresses(domain)
          if addrs.length > 0
            return addrs
          end
        end  
      rescue Timeout::Error => e
      end
    end
    return []
  end
  def print_domain(domain)
    response = get_domain(domain)
    if response.length > 0
      if !CACHE.nil?
        @cache_file.write("#{domain.gsub(@target, "\x7")}")
      end
      if @verbose
        puts "\e[32m#{domain}\e[0m :#{response.join("\e[2m/\e[0m")}"
      else
        $stdout.print domain + "\n"
      end
      if @out
        @out.write(domain+"\n")
      end
    end
  end
  def check_cache_domain
    if !CACHE.nil?
      if !File.file? CACHE+"/#{@target}.cache"
        File.open(CACHE+"/#{@target}.cache", "a")
      else
        File.open(CACHE+"/#{@target}.cache") do |f|
          data_ = f.read.split("\x7")
          data_ = data_.uniq
          data_.map do |s|
            if @show_new
              if @show_cache
                $stdout.print s+target+"\n"
              else
                puts "\e[32m#{s+@target}\e[0m"
              end
            end
          end
          File.open(CACHE+"/#{@target}.cache", "w") do |f2|
            f2.write(data_.join("\x7"))
          end
          return data_.map {|a| a[0,a.length-1] }
        end
      end
    end
    return []
  end
  def further_checkup
    begin
      req = Net::HTTP::get_response(URI("http://#{@target}"), {"User-Agent":rand_user_agent})
      if req.header["Location"][0,28] == "https://www.hugedomains.com/"
        print "enum-subdomain.rb: It redirect to #{req.header['Location'][0,28]}.The domain is under hugedomains for sale.\nDo you wanna exit ? "
        return true
      end
    rescue => e
    end
    return false
  end
  def brut
    already_have = check_cache_domain
    if @show_cache
      exit
    end
    if Resolv.getaddresses(@target).length == 0
      print "enum-subdomain.rb: No Dns records found for #{@target}.\nDo you wana exit ? "
      tmp = STDIN.gets.chomp
      if ["yes", 'y'].include? tmp
        print "\e[1A#{" "*60}\r"
        exit
      end
      print "\e[1A#{" "*60}\r"
    end
    if further_checkup
      tmp = STDIN.gets.chomp
      if ["yes", 'y'].include? tmp
        print "\e[1A#{" "*60}\r"
        exit
      end
      print "\e[1A#{" "*60}\r"
    end
    if !CACHE.nil?
      @cache_file = File.open(CACHE+"/#{@target}.cache", "a")
    end
    if @out
      @out = File.open(@out, "w")
    end
    wordlist_ = File.open(@wordlist).readlines.uniq
    if @show_cache_without_d
      already_have.map do |a|
        wordlist_.delete(a)
      end
    end
    wordlist_.map do |line|
      Thread::new do
        if !already_have.include? line.chomp
          print_domain(
            [line.chomp, @target.strip].join(".")
          )
        end
      end
      sleep 0.03
      while Thread::list.length > @max_thread;end
    end
    while Thread::list.length > 1;end
    if Thread::list.length == 1
      sleep 0.6
    end
  end
end

def  main
  init = Subdomain_enum::new()
  OptionParser.new do |optp|
    optp.banner = "\nUsage: enum-subdomain.rb [-h] [-v] [-w DICT] [-t MAXTHREAD] [-T TIMEOUT] [-o OUT] DOMAIN
des: enumarate subdomain with randomize dns. (#{VERSION})
ability: Once It get the subdomain via R(dns).
         It never enumarate again if you don't use '-C' flag.
         The data logs under ~/.cache/enum-subdomain/.
Eg: enum-subdomain.rb -v example.com\n\n"
    optp.program_name = "enum-subdomain"
    optp.summary_width = 14
    optp.program_name = "enum-subdomain"
    optp.version = VERSION

    optp.on('-v', 'Enable verbose mode.') do |v|
      init.verbose = v
    end
    optp.on('-t MAXTHREAD', Integer, "Maximum concurrency. (default:#{MAX_THREAD})") do |t|
      init.max_thread = t
    end
    optp.on('-w WORDLIST', "Use custom wordlist. (default:#{WORDLIST})") do |w|
      init.wordlist = w
    end
    optp.on('-T TIMEOUT', Integer, "Set time out for each try. (default:#{TIME_OUT}s)") do|t|
      init.timeout = t
    end
    optp.on('-o OUTPUT', "Append output to the file.")do|f|
      init.out = f
    end
    optp.on('-c', "Show cached subdomain and exit.") do|f|
      init.show_cache = true
    end
    optp.on('-C', "Ignore cached subdomain and enumarate again.")do |c|
      init.show_cache_without_d = false
      init.show_new = false
    end
    optp.on('-n', "Hide cached subdomain and show only new.") do |n|
      init.show_new = false
    end
    optp.on('-h', '--help', "Print this help banner.") do |h|
      puts optp
      exit
    end
  end.parse!
  init.target = ARGV[-1]
  if !init.target.nil?
    init.brut
  else
    puts "enum-subdomain.rb:OptionRequire: use -h or --help."
  end
end


begin
  main
rescue (OptionParser::MissingArgument) => e
  puts e
rescue (OptionParser::InvalidArgument) => e
  puts e
rescue (Interrupt) => e
  begin
    print "\r(ctl+c) to exit"
    while Thread::list.length > 1;end
  rescue (Interrupt) => e
  end
  puts "#{" "*10}\r\e[1A\e[C"
end
