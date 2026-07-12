#!/usr/bin/env ruby
# frozen_string_literal: true

require 'digest/sha1'
require 'stringio'
require 'zlib'

module Binhunt
  # = PackerDetector
  #
  # Detects packers and obfuscators in ELF binaries.
  # Checks signatures, entropy, headers, and baseline diffs.
  class PackerDetector
    VERSION = "1.0.0"

    # Known packer signatures (magic bytes + offsets)
    SIGNATURES = {
      "UPX" => {
        :name       => "UPX",
        :description => "Ultimate Packer for eXecutables",
        :offsets    => [0x3c, 0x40], # ELF header + program header
        :magic      => "\x92\x86\x1e\x42", # UPX2 magic
        :entropy    => 7.5,
        :sections   => ["UPX0", "UPX1"],
        :headers    => {
          "upx_header" => [0x3c + 0x18, 6],
        },
      },
      "PE" => {
        :name       => "Portable Executable",
        :description => "Windows PE format embedded in ELF",
        :offsets    => [0x40],
        :magic      => "\x4d\x5a", # MZ header
        :entropy    => 7.2,
        :sections   => [],
        :headers    => {
          "pe_magic" => [0x3c + 0x18, 2],
        },
      },
      "ASPack" => {
        :name       => "ASPack",
        :description => "Simple PE packer",
        :offsets    => [0x40],
        :magic      => "\x5a\x4d", # MZ reversed (sometimes)
        :entropy    => 7.3,
        :sections   => [],
        :headers    => {
          "aspak_magic" => [0x3c + 0x18, 2],
        },
      },
      "Themida" => {
        :name       => "Themida",
        :description => "Anti-debugging packer",
        :offsets    => [0x40],
        :magic      => "\x54\x68\x65\x6d", # "Them"
        :entropy    => 7.4,
        :sections   => [],
        :headers    => {
          "themida_magic" => [0x3c + 0x18, 4],
        },
      },
      "VMProtect" => {
        :name       => "VMProtect",
        :description => "Virtual machine protection",
        :offsets    => [0x40],
        :magic      => "\x56\x4d", # VM
        :entropy    => 7.3,
        :sections   => [],
        :headers    => {
          "vmprotect_magic" => [0x3c + 0x18, 2],
        },
      },
    }.freeze

    # Suspicious header patterns (offset: size)
    SUSPICIOUS_HEADERS = {
      "upx_header"   => [0x3c + 0x18, 6],
      "pe_magic"     => [0x3c + 0x18, 2],
      "aspak_magic"  => [0x3c + 0x18, 2],
      "themida_magic"=> [0x3c + 0x18, 4],
      "vmprotect_magic"=>[0x3c + 0x18, 2],
    }.freeze

    # ELF header offsets (relative to file start)
    ELF_OFFSETS = {
      :e_ident_ei_class => 0x00,
      :e_ident_ei_data  => 0x04,
      :e_ident_ei_osabi => 0x07,
      :e_type           => 0x12,
      :e_machine        => 0x16,
      :e_entry          => 0x1a,
      :e_phoff          => 0x20,
      :e_shoff          => 0x28,
      :e_flags          => 0x34,
      :e_ehsize         => 0x3c,
      :e_phentsize      => 0x3e,
      :e_phnum          => 0x40,
      :e_shentsize      => 0x42,
      :e_shnum          => 0x44,
      :e_shstrndx       => 0x46,
    }.freeze

    # ELF class constants
    ELFCLASS32 = 1
    ELFCLASS64 = 2

    # ELF data encoding
    ELFDATA2LSB = 1
    ELFDATA2MSB = 2

    # ELF OS/ABI
    ELFOSABI_NONE = 0

    # ELF types
    ET_EXEC   = 2
    ET_DYN    = 3
    ET_REL    = 4

    # ELF machine constants (Linux)
    EM_X86_64 = 62
    EM_386    = 3
    EM_ARM    = 40
    EM_AARCH64= 183

    def initialize(options = {})
      @options = options.merge({
        :entropy_threshold => 7.5,
        :section_min_size  => 256,
        :baseline_path     => nil,
      }).freeze
    end

    # Main entry point: analyze a binary file
    def detect(file_path)
      return { :error => "File not found", :file => file_path } unless File.exist?(file_path)

      begin
        data = File.binread(file_path)
        result = analyze_elf(data, file_path)
        result[:baseline] = compare_baseline(result[:data]) if @options[:baseline_path]
        result
      rescue StandardError => e
        { :error => "Analysis failed: #{e.message}", :file => file_path }
      end
    end

    # Parse ELF header and extract metadata
    def parse_elf_header(data)
      return nil unless data.length >= 0x40

      ei_class = data[ELF_OFFSETS[:e_ident_ei_class]].chr.to_i
      ei_data  = data[ELF_OFFSETS[:e_ident_ei_data]].chr.to_i
      ei_osabi = data[ELF_OFFSETS[:e_ident_ei_osabi]].chr.to_i

      # Validate ELF magic and class
      return nil unless data[0..1] == "\x7f\x45" && ["L", "B"].include?(data[2].chr)

      endian = ei_data == ELFDATA2LSB ? "<" : ">"
      e_class = (ei_class == ELFCLASS32) ? 4 : 8

      # Parse header fields based on class
      if e_class == 4
        e_type   = data[ELF_OFFSETS[:e_type]].unpack1("C", endian).to_i
        e_machine= data[ELF_OFFSETS[:e_machine]].unpack1("C", endian).to_i
        e_entry  = data[ELF_OFFSETS[:e_entry]].unpack1("I", endian).to_i
        e_phoff  = data[ELF_OFFSETS[:e_phoff]].unpack1("I", endian).to_i
        e_shoff  = data[ELF_OFFSETS[:e_shoff]].unpack1("I", endian).to_i
        e_ehsize = data[ELF_OFFSETS[:e_ehsize]].unpack1("C", endian).to_i
        e_phnum  = data[ELF_OFFSETS[:e_phnum]].unpack1("C", endian).to_i
        e_shnum  = data[ELF_OFFSETS[:e_shnum]].unpack1("C", endian).to_i
        e_shstrndx= data[ELF_OFFSETS[:e_shstrndx]].unpack1("C", endian).to_i

        {
          :class   => "32-bit",
          :data    => (ei_data == ELFDATA2LSB) ? "little-endian" : "big-endian",
          :osabi   => (ei_osabi == ELFOSABI_NONE) ? "UNIX System V" : "unknown",
          :type    => type_name(e_type),
          :machine => machine_name(e_machine),
          :entry   => e_entry,
          :phoff   => e_phoff,
          :shoff   => e_shoff,
          :ehsize  => e_ehsize,
          :phnum   => e_phnum,
          :shnum   => e_shnum,
          :shstrndx=> e_shstrndx,
        }
      else
        {
          :class   => "64-bit",
          :data    => (ei_data == ELFDATA2LSB) ? "little-endian" : "big-endian",
          :osabi   => (ei_osabi == ELFOSABI_NONE) ? "UNIX System V" : "unknown",
          :type    => type_name(e_type),
          :machine => machine_name(e_machine),
          :entry   => e_entry,
          :phoff   => e_phoff,
          :shoff   => e_shoff,
          :ehsize  => e_ehsize,
          :phnum   => e_phnum,
          :shnum   => e_shnum,
          :shstrndx=> e_shstrndx,
        }
      end
    end

    # Parse program headers and check for PE signatures
    def parse_program_headers(elf_header, data)
      return [] unless elf_header && elf_header[:phoff] && elf_header[:phnum] > 0

      endian = (elf_header[:data] == "little-endian") ? "<" : ">"
      e_class = (elf_header[:class] == "32-bit") ? 4 : 8

      phentsize = (e_class == 4) ? 32 : 56
      total_ph_size = elf_header[:phoff] + (elf_header[:phnum] * phentsize)

      headers = []
      if data.length > total_ph_size
        # Check for PE signature in program headers area
        pe_offset = elf_header[:phoff] + 0x18
        pe_magic = data[pe_offset, 2].unpack1("C*", endian).join.to_s

        headers << {
          :type => "PE",
          :offset => pe_offset,
          :magic => pe_magic,
          :size  => 2,
        } if pe_magic == "\x4d\x5a" || pe_magic == "\x5a\x4d"
      end

      headers
    end

    # Calculate Shannon entropy of a string/bytes
    def calculate_entropy(data)
      return 0.0 unless data.length > 0

      freq = Hash.new(0)
      data.each_byte { |b| freq[b] += 1 }

      total = data.length.to_f
      entropy = 0.0
      freq.each_pair do |_, count|
        p = (count / total).to_f
        entropy -= p * Math.log2(p) if p > 0
      end

      entropy.round(4)
    end

    # Calculate entropy of each section
    def calculate_section_entropies(elf_header, data)
      return {} unless elf_header && elf_header[:shoff] && elf_header[:shnum] > 0

      endian = (elf_header[:data] == "little-endian") ? "<" : ">"
      e_class = (elf_header[:class] == "32-bit") ? 4 : 8

      shentsize = (e_class == 4) ? 40 : 64
      total_sh_size = elf_header[:shoff] + (elf_header[:shnum] * shentsize)

      entropies = {}
      if data.length > total_sh_size
        # Parse section headers and calculate entropy for each
        elf_header[:shstrndx].times do |i|
          offset = elf_header[:shoff] + (i * shentsize)
          next unless offset + 32 < data.length

          sh_name_offset = [offset, offset + 0x18].max
          name_len = [data[sh_name_offset], data[sh_name_offset + 1]].compact.sum

          # Extract section name
          name_end = (sh_name_offset + name_len).min(data.length)
          name = data[sh_name_offset, name_len].unpack("C*").join

          # Calculate entropy for this section's content range
          sh_size = [data[offset], data[offset + 1]].compact.sum
          next if sh_size < @options[:section_min_size]

          content_start = offset + 32 # Skip header
          content_end = (offset + 32 + sh_size).min(data.length)
          entropy = calculate_entropy(data[content_start, content_end - content_start])

          entropies[name] = {
            :entropy => entropy,
            :size    => sh_size,
            :offset  => offset,
          }
        end
      end

      entropies
    end

    # Check for suspicious headers at known offsets
    def check_suspicious_headers(elf_header, data)
      return [] unless elf_header && data.length > 0x40

      endian = (elf_header[:data] == "little-endian") ? "<" : ">"
      e_class = (elf_header[:class] == "32-bit") ? 4 : 8

      suspicious = []
      shentsize = (e_class == 4) ? 40 : 64

      elf_header[:shstrndx].times do |i|
        offset = elf_header[:shoff] + (i * shentsize)
        next unless offset + 32 < data.length

        # Check for UPX header in section headers area
        upx_offset = [offset, offset + 0x18].max
        if data[upx_offset, 6] == "\x92\x86\x1e\x42" ||
           data[upx_offset, 6] == "\x42\x1e\x86\x92"
          suspicious << { :type => "UPX header", :offset => upx_offset }
        end

        # Check for PE signature in section headers area
        pe_magic = [data[offset], data[offset + 1]].compact.sum.join.to_s
        if pe_magic == "\x4d\x5a" || pe_magic == "\x5a\x4d"
          suspicious << { :type => "PE magic", :offset => offset }
        end

        # Check for Themida signature
        them_magic = [data[offset], data[offset + 1], data[offset + 2], data[offset + 3]].compact.sum.join.to_s
        if them_magic == "\x54\x68\x65\x6d"
          suspicious << { :type => "Themida magic", :offset => offset }
        end

        # Check for VMProtect signature
        vm_magic = [data[offset], data[offset + 1]].compact.sum.join.to_s
        if vm_magic == "\x56\x4d"
          suspicious << { :type => "VMProtect magic", :offset => offset }
        end
      end

      suspicious
    end

    # Main analysis function that combines all checks
    def analyze_elf(data, file_path)
      result = {
        :file       => file_path,
        :size       => data.length,
        :sha1       => Digest::SHA1.hexdigest(data),
        :header     => parse_elf_header(data),
        :ph_headers => parse_program_headers(nil, data),
        :entropies  => calculate_section_entropies(nil, data),
        :suspicious => check_suspicious_headers(nil, data),
      }

      # Check for packer signatures in header area
      result[:packers] = []
      if data.length > 0x40
        offset = [0x3c, 0x40].max
        upx_magic = data[offset, 6].unpack("C*").join.to_s

        # Check for UPX2 magic
        if upx_magic == "\x92\x86\x1e\x42" || upx_magic == "\x42\x1e\x86\x92"
          result[:packers] << { :name => "UPX", :offset => offset }
        end

        # Check for PE signature
        pe_magic = [data[offset], data[offset + 1]].compact.sum.join.to_s
        if pe_magic == "\x4d\x5a" || pe_magic == "\x5a\x