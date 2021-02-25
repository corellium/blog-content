// Script to gather the shared library from disk and also
// from memory utilizing Frida. After reading the file from
// disk, it will then compare some sections of the file in
// order to hunt and identify potentially modified and hooked
// functions.
//
// Re-written over the ages for usage while
// unpacking Android applications by
// Tim 'diff' Strazzere, <tim -at- corellium.com> <diff -at- protonmail.com>
// Based off older code and concepts from lich4/lichao890427
//
// Corresponding blog https://corellium.com/blog/android-frida-finding-hooks

// Helper function for creating a native function for usage
function getNativeFunction(name, ret, args) {
    var mod = Module.findExportByName(null, name);
    if (mod === null) {
        return null;
    }

    var func = new NativeFunction(mod, ret, args);
    if (typeof func === 'undefined') {
        return null;
    }

    return func;
}

var open_ptr = getNativeFunction('open', 'int', ['pointer', 'int', 'int']);
var read_ptr = getNativeFunction('read', 'int', ['int', 'pointer', 'int']);
var close_ptr = getNativeFunction('close', 'int', ['int']);
var lseek_ptr = getNativeFunction('lseek', 'int', ['int', 'int', 'int']);

function getElfData(module) {
    console.log('Processing ', module.path);
    if (module.sections) {
        return true;
    }

    var fd = open_ptr(Memory.allocUtf8String(module.path), 0 /* O_RDONLY */, 0);
    if (fd == -1) {
        return false;
    }

    // Get elf header
    var header = Memory.alloc(64);
    lseek_ptr(fd, 0, 0 /* SEEK_SET */);
    read_ptr(fd, header, 64);

    // Allow for both 32bit and 64bit binaries
    var is32 = Memory.readU8(header.add(4)) === 1;
    module.is32 = is32;

    // Parse section headers
    var sectionHeaderOffset = is32 ? Memory.readU32(header.add(32)) : Memory.readU64(header.add(40)).toNumber(); // For some reason this is read as a string
    var sectionHeaderSize = is32 ? Memory.readU16(header.add(46)) : Memory.readU16(header.add(58));
    var sectionHeaderCount = is32 ? Memory.readU16(header.add(48)) : Memory.readU16(header.add(60));
    var sectionHeaderStringTableIndex = is32 ? Memory.readU16(header.add(50)) : Memory.readU16(header.add(62));

    var sectionHeaders = Memory.alloc(sectionHeaderSize * sectionHeaderCount);

    lseek_ptr(fd, sectionHeaderOffset, 0 /* SEEK_SET */);
    read_ptr(fd, sectionHeaders, sectionHeaderSize * sectionHeaderCount);

    var stringTableOffset = is32 ? Memory.readU32(sectionHeaders.add(sectionHeaderSize * sectionHeaderStringTableIndex + 16)) : Memory.readU64(sectionHeaders.add(sectionHeaderSize * sectionHeaderStringTableIndex + 24)).toNumber();
    var stringTableSize = is32 ? Memory.readU32(sectionHeaders.add(sectionHeaderSize * sectionHeaderStringTableIndex + 20)) : Memory.readU64(sectionHeaders.add(sectionHeaderSize * sectionHeaderStringTableIndex + 32)).toNumber();

    var stringTable = Memory.alloc(stringTableSize);
    lseek_ptr(fd, stringTableOffset, 0 /* SEEK_SET */);
    read_ptr(fd, stringTable, stringTableSize);
    var sections = [];

    var dynsym = undefined;
    var dynstr = undefined;
    var relplt = undefined;
    var reldyn = undefined;
    
    for (var i = 0; i < sectionHeaderCount; i++) {
        var sectionName = Memory.readUtf8String(stringTable.add(Memory.readU32(sectionHeaders.add(i * sectionHeaderSize))));
        var sectionAddress = is32 ? Memory.readU32(sectionHeaders.add(i * sectionHeaderSize + 12)) : Memory.readU64(sectionHeaders.add(i * sectionHeaderSize + 16)).toNumber();
        var sectionOffset = is32 ? Memory.readU32(sectionHeaders.add(i * sectionHeaderSize + 16)) : Memory.readU64(sectionHeaders.add(i * sectionHeaderSize + 24)).toNumber();
        var sectionSize = is32 ? Memory.readU32(sectionHeaders.add(i * sectionHeaderSize + 20)) : Memory.readU64(sectionHeaders.add(i * sectionHeaderSize + 32)).toNumber();

        if (['.text', '.rodata', '.got', '.got.plt'].includes(sectionName)) {
            var section = {};
            section.name = sectionName;
			section.memoryOffset = sectionAddress;
			section.fileOffset = sectionOffset;
            section.size = sectionSize;
            if (sectionSize > 0) {
                section.data = Memory.alloc(sectionSize);
                lseek_ptr(fd, sectionOffset, 0 /* SEEK_SET */);
                read_ptr(fd, section.data, sectionSize);
            } else {
                section.data = undefined;
            }
            sections.push(section);
        } else if (['.dynsym', '.dynstr', '.rel.dyn', '.rel.plt'].includes(sectionName)) {
            var section = {};
            section.name = sectionName;
			section.memoryOffset = sectionAddress;
			section.fileOffset = sectionOffset;
            section.size = sectionSize;
            if (sectionSize > 0) {
                section.data = Memory.alloc(sectionSize);
                lseek_ptr(fd, sectionOffset, 0 /* SEEK_SET */);
                read_ptr(fd, section.data, sectionSize);
            } else {
                console.log('No data section for', section.name);
                section.data = undefined;
            }

            if (section.name === '.dynsym') {
                dynsym = section;
            }
            if (section.name === '.dynstr') {
                dynstr = section;
            }
            if (section.name === '.rel.dyn') {
                reldyn = section;
            }
            if (section.name === '.rel.plt') {
                relplt = section;
            }
            sections.push(section);
        }
    }

    if (!!dynsym && !!dynstr) {
        var symbols = [];
        var stringTable = module.base.add(dynstr.memoryOffset);
        var structSize = is32 ? 16 : 24;
        for (var i = 0; i < dynsym.size / structSize; i++) {
            var symbolOffset = Memory.readU32(module.base.add(dynsym.memoryOffset).add(structSize * i));
            symbols.push(Memory.readUtf8String(stringTable.add(symbolOffset)));
        }

        module.symbols = symbols;
    }

    var relmap = new Map();
    if (!!reldyn) {
        for (var i = 0; i < reldyn.size / 8; i++) {
            if ((Memory.readU32(module.base.add(reldyn.memoryOffset).add(i * 8)) != 0) &&
                (Memory.readU32(module.base.add(reldyn.memoryOffset).add(i * 8).add(4)) >> 8 != 0)) {
                relmap[Memory.readU32(module.base.add(reldyn.memoryOffset).add(i * 8))] = Memory.readU32(module.base.add(reldyn.memoryOffset).add(i * 8).add(4)) >> 8;
            }
        }
    }

    if (!!relplt) {
        for (var i = 0; i < relplt.size / 8; i++) {
            if ((Memory.readU32(module.base.add(relplt.memoryOffset).add(i * 8)) != 0) &&
                (Memory.readU32(module.base.add(relplt.memoryOffset).add(i * 8).add(4)) >> 8 != 0)) {
                relmap[Memory.readU32(module.base.add(relplt.memoryOffset).add(i * 8))] = Memory.readU32(module.base.add(relplt.memoryOffset).add(i * 8).add(4)) >> 8;
            }
        }
    }
    module.relmap = relmap;

    module.sections = sections;
    return true;
}

function findHooks(module) {
    if (module.sections === undefined) {
        if (!getElfData(module)) {
            return undefined;
        }
    }

    module.sections.forEach((section) => {
        if (section.size === 0) {
            return;
        }

        // It's important to cast the ArrayBuffer returned by `readByteArray` cannot be referenced incrementally
        var file = new Uint8Array(Memory.readByteArray(section.data, section.size));
        var memory = new Uint8Array(Memory.readByteArray(module.base.add(section.memoryOffset), section.size));
        for (var i = 0; i < section.size;) {
            if (['.rodata', '.text'].includes(section.name)) {
                if (file[i] != memory[i]) {
                    console.log('*** Potential variance found at ', DebugSymbol.fromAddress(module.base.add(section.memoryOffset).add(i)));
                    i += 4;
                }
                i++
            } else if (['.got'].includes(section.name)) {
                break;
                // It shouldn't be as the got table isn't initialized until execution
                if (file[i] != memory[i]) { 
                    // todo compare the symbol to string against what it resolves too
                }
                i += module.is32 ? 4 : 8;
            } else {
                // Unscanned sections, to be added as needed
                break;
            }
        }
    });
}

// Quick and simple way to get the package name, assumes that the script
// was injected into an APK otherwise it won't work.
function getPackageName() {
    var fd = open_ptr(Memory.allocUtf8String('/proc/self/cmdline'), 0 /* O_RDONLY */, 0);
    if (fd == -1) {
        return 'null';
    }

    var buffer = Memory.alloc(32);
    read_ptr(fd, buffer, 32);
    close_ptr(fd);

    return Memory.readUtf8String(buffer);
}

// Adjust this as needed, often I don't need to scan anything outside of the
// included shared libraries and a few which are almost always in an apex folder.
// This logic will need to be changed if you're using a pre-apex version of Android
// to ensure it picked up the proper libraries for hunting
//
// While it doesn't hurt to scan everything, it's almost never needed and will just slow
// down the process at a linear scale.
//
// If you already know what you're hunting for, feel free to just return or look for
// libart, libdvm, etc, etc
function getRelevantModules() {
    var modules = [];
    var packagename = getPackageName();

    Process.enumerateModules().forEach((module) => {
        if (module.path.includes(packagename)) {
            modules.push(module);
            console.log('Adding ', module.path);
        } else if (module.path.includes('/apex')) {
            modules.push(module);
            console.log('Adding ', module.path);
        } else {
            console.log('Skipping ', module.path);
        }
    })

    return modules;
}

var modules = getRelevantModules();

modules.forEach((module) => {
    getElfData(module);
    findHooks(module);
});
