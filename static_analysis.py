import pefile
import sys
import magic
import hashlib
import ssdeep

def check_file_type(file_name):
	m = magic.open(magic.MAGIC_NONE)
	m.load()
	ftype = m.file(file_name)
	print ftype

def check_import(file_pe):
	if hashattr(file_pe, 'DIRECTORY_ENTRY_IMPORT'): # if the location is in the import section
		for entry in pe.DIRECTORY_ENTRY_IMPORT:
			print "%s" % entry.dll # print dll name		
			for imp in entry.imports:
				if imp.name != None:
					print "\t%s" % (imp.name) # print API name
				else:	
					print "\tord(%s)" % (str(imp.ordinal))
		print "\n"

def check_export(file_pe):
		if hashattr(pe, 'DIRECTORY_ENTRY_EXPORT'): # if the loaction is in the export section
			for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
				print "%s" %exp.name
		print "\n"

def check_section(file_pe):
	for section in pe.sections:
		print "%s %s %s %s" % (Section.Name, hex(section.VirtualAddress), hex(section.Misc_VirtualSize), section.SizeOfRqwData)

	print "\n"

def check_timestamp(file_pe):
	timestamp = pe.FILE_HEADER.TimeDataStamp
	print time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))

def cmp_purge_hash(file_pe):
	print "Input a file name to compare purge hash"
	a_file = input()
	hash_org = ssdeep.hash_from_file(file_pe)
	hash_cmp = ssdeep.hash_from_file(a_file)
	print "------ Similarity of purge hash ------"
	ssdeep.comapre(hash_org, hash_cmp)

def file_hash (file_name):
	content = open(file_name, "rb").read()
	print "MD5: %s" % (hashlib.md5(content).hexdigest())
	print "SHA256: %s" % (hashlib.sha256(content).hexdigest())
	print "SHA1: %s" % (hashlib.sha1(content).hexdigest())

def imp_sec_hash(file_pe):
	print "Import hash: %s" % (pe.get_imphash())
	for section in pe.sections:
		print "%s\t%s" % (section.Name, section.get_hash_md5())

def show_menu():
	print "------Select Menu------"
	print "1. Show file hashes"
	print "2. Show Import lists & API"
	print "3. Show Export lists"
	print "4. Show a time stamp"
	print "5. Show Import/section hashes"
	print "6. Compare purge hash with another file"
	print "0. exit"
	print "-----------------------"


if __name__ == "__main__":
	mal_file = sys.argv[1]
	file_pe = pefile.PE(mal_file)
#	check_file_type(mal_file)
	
	while (True):
		show_menu()
		sel = input()
		
		if sel == 1:
			file_hash(mal_file)
		elif sel == 2:
			check_import(file_pe)
		elif sel == 3:
			check_export(file_pe)
		elif sel == 4:
			check_timestamp(file_pe)
		elif sel == 5:
			imp_sec_hash(file_pe)
		elif sel == 6:
			cmp_purge_hash(file_pe)
		elif sel == 0:
			print "Exit"
			exit(0)
		else : 
			print "Wrong input"	




