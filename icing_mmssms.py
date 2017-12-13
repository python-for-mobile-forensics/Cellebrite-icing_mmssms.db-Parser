#Written by Chris Weber -----Ctrl_Klick Forensics
#chrisw706@gmail.com

#script parses messages that are stored in the icing_mmssms.db and it's journal file.

from physical import*
import re
from binascii import hexlify

# This is the pattern used to pull messages in into a list.  But it also pulls other stuff into the list that are
#not messages.  We will get rid of those things later.
string = '''\x73\x6D\x73\x63\x6F\x6E\x74\x65\x6E\x74[\x00-\xff]*?[\x5A\x15]|[\5A\x14]|[\x73\x6D\x73\x63\x6F\x6E\x74\x65\x6E]'''


filePath = '/Root/data/com.google.android.gms/databases/icing_mmssms.db'
#Searches through the partitions and looks for the icing_mmssms.db.  It get the db and the journal file.
for fs in ds.FileSystems:
	for file in fs.Search(filePath):
		if file.AbsolutePath.endswith('icing_mmssms.db') or file.AbsolutePath.endswith('icing_mmssms.db-journal'):
			# reads the fils and searches for the messages
			f = file.read()
			reResults = re.findall(string,f)
			#creates a list called messages and filters out the messages that are not really messages
			messages = []
			for item in reResults:
				if item.startswith("smscontent") and item[19:25] != "unread":
					if item.endswith("Z"):
						messages.append(item[:-1])
					else:
						messages.append(item)

			for message in messages:
				newSms = SMS()
				pa = Party()
				#Checks the byte location for sent to see if it is a 2 and set the value for sent or Inbox		
				in_out = hexlify(message[19])
				if in_out == '02':
					pa.Role.Value = PartyRole.To
					newSms.Folder.Value = "Sent"
				else:
					pa.Role.Value = PartyRole.From
					newSms.Folder.Value = "Inbox"
				# uses regular expression search for the phone number/date/time,body
				# the expression puts each part in a groups so we can add them to the table
				dateMessage = re.search('''(\d+)(\x01[\x00-\xff]{5})(.*)''',message[19:])
				pa.Identifier.Value = str(dateMessage.group(1))
				newSms.TimeStamp.Value = TimeStamp.FromUnixTime(int(hexlify(dateMessage.group(2)),16)/1000)
				newSms.Body.Value = dateMessage.group(3)			
				newSms.Source.Value = str(file)
				newSms.Parties.Add(pa)
				ds.Models.Add(newSms)



