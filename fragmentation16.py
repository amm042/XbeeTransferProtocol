'''
quick and dirty fragmentation library.

supports up to 2**16 fragments. 

uses a global buffer for decoding so you can only have one message
in flight at a time, or fragments will get lost.
'''


import zlib
import math
import struct

MAGIC = 0x17
class CrcError(Exception): pass

class Fragment():
    def __init__(self, frag_num, total_frags, crc, data):
        self.num = frag_num
        self.total = total_frags
        self.crc = crc
        self.data = data


def encode(frag_num, total_frags, crc, frag):        
    h = struct.pack(">BHHL", MAGIC, total_frags, frag_num, crc )
    #print(h, frag)        
    return h + frag
def decode(frag):    
     # 0   1 2   3 4   4 5 6 7      
    m, tf, cf, crc = struct.unpack(">BHHL", frag[0:9])
    #print(m, tf, cf, crc)
    return m, tf, cf, crc, frag[9:]
def make_frags(data, threshold=121, encode = True):
    '''given some data (binary string) add the fragmentation header and 
        fragment if necessary. Adds 6 bytes of overhead, so threshold of 
        121 will generate a max packet length of 127 bytes.
        returns generated fragments with appropriate headers.    
       '''   
    
    at=0
    frag_num =0
    # make total frags the 0-based frag number of the last fragment, 
    # so it is actually total_frags - 1...
    total_frags = math.floor(len(data) / float(threshold))
    crc = zlib.crc32(data) 
    #print('crc is ', crc)
    if total_frags > 0xffff:
        raise Exception("data too large for this format ({} is too many fragments)!".format(total_frags))
    while at<len(data):
        frag_data = data[at:at+threshold] 
        at += len(frag_data)
        if encode:
            yield encode(frag_num, total_frags, crc, frag_data)
        else:
            yield Fragment(frag_num, total_frags+1, crc, frag_data)
            
        frag_num += 1
        
frag_buf = {} 
def receive_frag(frag):
    global frag_buf
    
    magic, total_frags, this_frag, crc, frag_data = decode(frag)
    #print("rcv ", total_frags,this_frag, crc, frag_data)
    if magic != MAGIC:
        return None
    frag_buf[this_frag] = (crc, frag_data)
    
    if this_frag == total_frags: 
        # attempt to reassemble
        r = b''
        for i in range(total_frags+1):
            r += frag_buf[i][1]
        mycrc = zlib.crc32(r)
        if mycrc == crc:
            return r
        else:            
            #print('got crc {:x} != {:x}'.format(mycrc, crc))
            raise CrcError()
    return None

if __name__=="__main__":
    #test

    s= b'test'
    rslt = None
    for frag in make_frags(s):
        rslt = receive_frag(frag)
        
    assert rslt == s, "got {}".format(rslt)
    
        
    s=b'''Lorem ipsum dolor sit amet, consectetur adipiscing elit. Duis commodo sodales sem, sed ultrices lacus facilisis vitae. Curabitur sapien neque, aliquet vitae euismod ac, ornare egestas urna. Curabitur convallis mauris ligula, vel tempus dui porttitor quis. Sed ultricies leo turpis, vitae sagittis sem pretium aliquam. Donec eleifend id turpis ac tincidunt. Quisque leo nisi, faucibus id tincidunt id, gravida vehicula arcu. Donec volutpat rhoncus tincidunt. Proin id pharetra ex. Praesent sed urna tempor, semper felis eget, ultricies nulla. Nulla facilisi. Curabitur et augue porttitor, gravida felis a, vulputate neque. Sed et interdum risus, eget rutrum mauris. Pellentesque volutpat purus ut metus malesuada ultricies. Fusce feugiat, mauris non tempor vulputate, quam mi luctus odio, a posuere libero nisl nec felis.
Proin eget elit condimentum, hendrerit lacus quis, dignissim tellus. In congue semper finibus. Ut elementum, nibh non condimentum posuere, felis risus porttitor ligula, commodo molestie ligula elit a ligula. Sed non libero faucibus metus euismod porta ac nec ligula. Sed pharetra, velit eu pellentesque dignissim, dolor magna dapibus libero, sit amet volutpat sem tortor quis neque. Etiam ut bibendum risus. Phasellus blandit sodales sapien. Nunc sollicitudin accumsan lectus pretium lobortis. Quisque eget pretium orci. Pellentesque mauris enim, finibus vitae imperdiet non, fringilla a ex. Nam justo sapien, elementum nec risus eu, tincidunt lobortis risus. Nunc ut justo sed augue dignissim placerat. Phasellus eget ipsum rhoncus tortor tempor faucibus. Curabitur iaculis massa pellentesque, semper sapien luctus, commodo justo. Aenean a consequat quam, a vehicula risus. Proin erat tellus, pulvinar vitae dictum in, sodales quis orci.'''
    
    rslt = None
    for frag in make_frags(s):
        rslt = receive_frag(frag)
        
    assert rslt == s, "got {}".format(rslt) 
    
    s= b'''Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed diam justo, tincidunt eu fringilla non, aliquet vel tortor. Suspendisse risus sapien, fermentum nec eros sed, accumsan iaculis massa. Donec et felis vel ligula facilisis maximus. Pellentesque tempor orci ut blandit tempus. Pellentesque euismod enim id suscipit dictum. Nunc justo dui, laoreet vel diam sed, gravida suscipit velit. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Nunc fringilla ligula nulla. Nullam convallis ac elit eu dapibus.

Suspendisse vitae arcu auctor, ornare ligula eget, porttitor ligula. Sed interdum, felis eget sagittis rutrum, nulla quam varius neque, et consectetur metus enim in tellus. Duis imperdiet urna nec consectetur ultricies. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Donec leo orci, ullamcorper ut neque at, condimentum volutpat ex. Donec pulvinar nisl condimentum nunc dictum, vel porta est lacinia. Vestibulum ut mattis urna. Donec at sagittis erat. Curabitur blandit nisl vitae eleifend consectetur.

Maecenas venenatis sagittis dui in iaculis. Aliquam bibendum enim lectus, sed ullamcorper ligula convallis at. Duis pretium porta maximus. Duis nec scelerisque leo. Quisque viverra vestibulum augue sit amet cursus. Quisque ut sapien libero. Etiam pellentesque leo et dolor aliquet sodales. Aenean eget ex id sem condimentum consequat volutpat eget felis. Sed augue mauris, porttitor et mollis nec, hendrerit et tortor.

Maecenas nec condimentum diam. Proin tristique nunc eu orci auctor porta. Aliquam porta urna ut rhoncus lobortis. Sed velit quam, consectetur a hendrerit eu, interdum malesuada nulla. Donec lacinia sed arcu ut faucibus. Aliquam gravida auctor varius. Morbi cursus nisl eget pharetra dictum. Nullam eu eros ut lacus egestas volutpat ut sed tellus. Aliquam pretium turpis sit amet lacinia ultricies. Praesent pellentesque justo quis metus gravida rhoncus. Aliquam erat volutpat. Ut vitae auctor nibh, tincidunt rhoncus lacus. Ut non dolor odio. Donec non varius est. Integer nunc leo, egestas ac enim a, viverra mattis sapien. Ut vitae dui nec diam lobortis ornare in non ipsum.

Proin sed fringilla justo. Suspendisse tincidunt sed sem non pellentesque. Donec dictum magna vulputate tellus laoreet convallis. Maecenas efficitur eros vel tellus auctor, ut efficitur nulla aliquet. Maecenas pellentesque, massa dignissim ornare aliquam, mi nunc varius lorem, in imperdiet metus dolor at mi. Nam ullamcorper, arcu eu blandit lacinia, nibh nisl aliquet tellus, ac tempus lacus sapien in metus. Aliquam eu dictum augue. Aliquam facilisis lectus odio, in tincidunt odio pulvinar pulvinar. Sed felis ipsum, molestie eu elementum sit amet, aliquam nec nisl. Morbi vestibulum magna vitae velit dignissim, ut sollicitudin nulla pulvinar. Etiam nec odio placerat, bibendum ligula accumsan, vulputate elit.

Vestibulum eget vulputate nulla. Maecenas sed efficitur elit. Phasellus fringilla purus a ante scelerisque, eget feugiat tellus commodo. Fusce mattis cursus dolor, sed condimentum sem lacinia eu. Nulla ultricies mauris vel magna vestibulum ornare. Mauris vehicula quam at purus faucibus finibus. Nulla porttitor mauris quis tincidunt iaculis. Maecenas sed urna dapibus, pretium ligula non, congue est. Vestibulum ultricies felis ut lacus sollicitudin, nec porttitor massa pellentesque. Vestibulum quis eleifend mauris. Donec facilisis imperdiet lectus, sit amet eleifend urna aliquet sed. Morbi feugiat vestibulum nisi at hendrerit.

Aenean tristique metus augue, ac ultricies ante egestas ac. Praesent mollis suscipit nisi, sed porttitor nulla dapibus non. Proin vel nulla aliquam, finibus erat quis, venenatis tellus. Quisque quis eros est. Aenean congue malesuada purus vel vehicula. Duis condimentum lacus lacus, non consequat neque elementum et. Fusce porttitor, nunc at porttitor convallis, quam enim fermentum velit, eu tempus velit est laoreet justo. Quisque dapibus, metus imperdiet cursus consectetur, erat enim scelerisque felis, ultrices sodales diam mauris a elit. Donec ante lectus, vehicula sit amet molestie vel, feugiat dignissim massa. Donec in consectetur ipsum.

Etiam nunc elit, accumsan id dignissim nec, mollis tempor ante. Praesent mattis, ex et vestibulum imperdiet, nulla nulla hendrerit ligula, et rhoncus massa est vitae massa. Vestibulum lacinia luctus imperdiet. Aenean egestas, erat et consectetur pharetra, orci felis tempor arcu, eget vestibulum metus nunc in nunc. Ut ut efficitur turpis. Nulla lacinia tellus et libero semper, ac tincidunt sem venenatis. Fusce rutrum id libero ac porttitor. Cras consequat ipsum dui, vulputate elementum massa congue id. Donec et ante nulla. Vestibulum pretium diam id scelerisque finibus.

Nulla faucibus vel leo vitae egestas. Quisque nec maximus purus, eget fermentum lorem. Nam vehicula hendrerit fermentum. Quisque id risus sit amet lectus aliquam convallis in dignissim odio. Aenean et felis a dui feugiat euismod. Nullam pharetra, ipsum vel pellentesque sodales, erat enim auctor tellus, a vehicula ipsum ex eget neque. Mauris tortor nulla, finibus iaculis accumsan quis, molestie at ante. Cras sed nibh non neque ultrices consectetur vel sit amet urna. Integer quam ipsum, eleifend eget auctor sed, eleifend eget velit. Sed quis ligula dui. Aenean ultricies rutrum sapien in efficitur. Etiam eget cursus ex. Nulla facilisi. Aliquam consequat gravida quam, in vehicula diam suscipit id. Vestibulum at vulputate mi, sit amet congue nunc.

Phasellus id arcu sapien. Nullam ut risus nec nibh molestie elementum eu eget dui. Praesent ut justo mollis, tristique velit eu, eleifend ex. Maecenas fermentum bibendum pulvinar. Morbi mollis augue at egestas commodo. Morbi pharetra rutrum velit, eget feugiat libero gravida nec. Duis quis sodales odio. Maecenas vestibulum vel ipsum quis volutpat. Phasellus eleifend eu velit in venenatis. Nunc nisl sem, vulputate sed porta non, porta ac magna. In feugiat viverra nulla, ac tempus lorem tempus id.

Praesent aliquet diam elit. Fusce est elit, consectetur a arcu at, scelerisque sodales ex. Suspendisse ipsum urna, venenatis et est in, rhoncus aliquet odio. Praesent leo tellus, porta a dolor ut, posuere porttitor velit. Cras sed nisi ut lacus consectetur malesuada ac eget augue. Phasellus vestibulum metus ex, at tristique ligula sagittis et. Praesent luctus gravida interdum.

Morbi faucibus vitae lacus id consectetur. Nulla facilisi. Sed tempus a massa eu fringilla. Integer fringilla ultrices sem. Phasellus convallis ex enim, eu lobortis nisi tincidunt id. Suspendisse mollis lorem vitae faucibus efficitur. Sed mattis ultrices ipsum quis lacinia. Ut hendrerit pretium enim eget sollicitudin. Quisque consequat efficitur luctus. Praesent euismod augue quis erat cursus pellentesque.

Nunc sed gravida metus. Donec lobortis magna vel lobortis sodales. In luctus laoreet mi nec tincidunt. Etiam rhoncus sed elit ut ultrices. Proin pellentesque arcu vitae condimentum cursus. Aenean a ipsum pulvinar, iaculis mauris eu, pellentesque arcu. Duis vitae ante a ante interdum aliquet. Morbi rhoncus metus nec est fermentum facilisis. Etiam euismod rutrum ligula, non elementum risus elementum ut. In hendrerit maximus nisi, in tincidunt purus imperdiet sit amet. Nam blandit accumsan quam, vel varius nisl posuere vitae. Aliquam erat ex, dapibus id sodales sit amet, viverra et felis. Fusce molestie ligula lacus, ut tristique diam placerat nec.

Nunc lacus libero, auctor nec ante bibendum, interdum porttitor nisl. Fusce tellus arcu, mollis nec turpis et, hendrerit tristique nisl. Maecenas a tortor iaculis, dignissim sapien id, imperdiet sapien. Nam non erat eget velit posuere porttitor. Pellentesque bibendum blandit nibh eu varius. Nulla pulvinar dui nec libero rhoncus sollicitudin. Suspendisse tempor odio mi, at rhoncus nibh congue in. Nunc dapibus erat id tempus imperdiet. Morbi maximus pellentesque ante sed maximus. Maecenas tortor elit, scelerisque sit amet rutrum eget, elementum eget ante.

Sed gravida odio sit amet risus cursus, quis commodo mi tempor. Vestibulum at sollicitudin lorem, eu posuere diam. Phasellus elit sem, mattis a scelerisque auctor, porttitor id dolor. Suspendisse feugiat sed magna id iaculis. Nunc rhoncus nulla ut purus suscipit maximus. Ut in ex quis felis posuere pretium. Aliquam quis lectus suscipit felis viverra hendrerit id et justo. Donec quis dignissim purus, non dapibus justo. Nulla ornare dolor id ipsum gravida, eget tincidunt felis feugiat. Fusce id auctor lectus, quis malesuada leo. Vivamus lobortis risus neque, eu maximus eros gravida et. Suspendisse potenti. Praesent congue malesuada sem at consequat.

Cras sagittis nibh eget nibh fringilla tincidunt. Maecenas in libero sapien. Pellentesque dapibus leo gravida felis egestas, sit amet ullamcorper eros viverra. Proin eleifend venenatis est in tincidunt. Vestibulum vehicula tempor tortor a accumsan. Quisque non orci cursus, posuere ante ut, placerat enim. Suspendisse potenti. Quisque ut ligula imperdiet, efficitur tellus ut, vestibulum lectus. Vestibulum ante magna, auctor nec suscipit sed, auctor quis tellus. Quisque non purus vitae nisi tristique consequat. Duis non mollis odio. Nam orci nulla, varius ut lectus in, accumsan fringilla ipsum. Pellentesque vitae feugiat risus. Curabitur elit nisl, vulputate ac facilisis ac, dapibus ut quam. Proin bibendum commodo eros quis varius. Vivamus vitae odio lacinia, varius metus vitae, tincidunt ante.

Nunc pulvinar finibus malesuada. Praesent commodo eleifend vulputate. Nam blandit vel odio eget mattis. Aliquam gravida libero nibh, eu ullamcorper ex accumsan vel. Curabitur nisl dolor, ullamcorper ac rhoncus nec, pharetra sed mi. Vivamus gravida sollicitudin libero, ut aliquet libero ullamcorper non. Ut convallis sem non ante finibus consequat sed sed metus. Duis egestas arcu dapibus nibh consectetur semper.

Sed lacinia nunc at ullamcorper aliquet. Donec efficitur sed felis ac commodo. Proin nec lacinia magna, lacinia varius mi. Nullam pulvinar et ipsum eget hendrerit. Phasellus dapibus bibendum sem in pellentesque. Ut massa elit, cursus a velit in, rutrum maximus est. Donec finibus mauris eget sapien sollicitudin, non vulputate ligula convallis. Donec vitae nisl non nunc fermentum feugiat sed vel justo. Fusce pellentesque sem purus, at imperdiet nisi rutrum quis. Integer vel risus nibh. Aenean risus dolor, hendrerit ut risus et, dapibus condimentum neque. Fusce tincidunt, ex nec mollis mattis, lacus lectus dapibus ex, nec aliquam enim elit eget nisl. Duis et nisi sed tortor molestie placerat. Cras elit eros, feugiat eu orci vel, egestas viverra eros. Nunc et ex sed nulla placerat convallis.

Donec accumsan dignissim arcu at consequat. In imperdiet maximus enim ut mattis. Praesent in tristique eros, vel efficitur leo. Nulla eget porttitor ante, eu volutpat nunc. Curabitur nec fermentum nibh, a molestie purus. Curabitur rutrum ex massa, at dapibus dolor dictum at. Curabitur eu semper sem, sit amet gravida orci. Fusce quis tellus et ante pretium pretium id eget lorem. Sed elit mauris, suscipit quis cursus ac, aliquet faucibus orci. Aliquam erat volutpat. Fusce suscipit lectus id interdum posuere.

Maecenas ullamcorper, magna in viverra finibus, nisl lectus ultrices ligula, sed laoreet turpis velit a dui. Mauris et vulputate augue. Phasellus vitae mi faucibus, consectetur nunc et, imperdiet nisi. Praesent sed consequat eros, in dignissim ex. Suspendisse commodo consectetur dui id pharetra. Quisque pharetra ultricies elit, sit amet convallis nulla tempor ultricies. Pellentesque justo arcu, dapibus in elit non, pellentesque vulputate nibh. Quisque sit amet urna ex. In nec sollicitudin nunc, vel sollicitudin ipsum. Vivamus neque ante, pretium ut urna id, egestas volutpat diam. Sed consequat nisl massa, non auctor nunc hendrerit pretium. Fusce eget sem felis. Donec pretium sapien in accumsan fermentum. Aliquam erat volutpat. Cras eget augue ligula.

Maecenas felis justo, luctus nec blandit vitae, luctus vitae massa. Sed faucibus semper orci at rutrum. Donec sit amet scelerisque risus. Fusce rutrum elit ac eleifend ultrices. Duis laoreet feugiat urna vel ullamcorper. Suspendisse hendrerit vulputate feugiat. Aliquam dapibus nulla lectus, eget dapibus arcu tempus at. Nulla vel ante libero. Morbi semper, turpis non tempus sodales, metus odio iaculis nisi, eu cursus nisl leo vitae elit. Cras maximus faucibus aliquam.

Fusce tempus magna erat, sit amet ullamcorper lorem consequat id. Nam a nibh et libero lobortis mollis. Morbi nec auctor odio. Praesent finibus pellentesque nunc eu eleifend. Pellentesque id tortor et massa ultricies ultrices. Aenean maximus aliquam eros vel accumsan. Nulla facilisi.

Nunc in ligula augue. Duis tempus felis eget viverra ullamcorper. Cras viverra enim at nunc porttitor faucibus. Donec tristique interdum sodales. Maecenas commodo posuere convallis. Curabitur in nunc id arcu efficitur tincidunt ut id tellus. Donec id consectetur nisl. Suspendisse eu orci ultrices, fermentum nunc at, aliquet justo. Nulla vestibulum, turpis non vestibulum varius, erat lacus sollicitudin augue, id pulvinar leo ligula quis neque. Vivamus et lorem facilisis, aliquam augue a, vehicula lectus. Sed fringilla arcu id euismod vestibulum. Proin posuere eros eros, condimentum suscipit orci sodales et. Phasellus blandit posuere felis, vel porttitor est iaculis nec. Duis ornare urna justo, eget venenatis odio feugiat sit amet. Nulla quam libero, molestie nec laoreet in, luctus nec dui. Morbi sed euismod ligula.

Sed dignissim nisl non libero eleifend sollicitudin. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Cras ultricies eros non turpis fermentum, eu egestas risus condimentum. Sed fermentum tristique lacus, at dictum mauris pharetra consequat. Nullam vel bibendum tellus, sit amet semper massa. Ut eget pulvinar velit, ac congue neque. Sed luctus metus at sodales posuere. Etiam aliquet massa sit amet ullamcorper maximus. Donec tempus orci sed purus malesuada vulputate. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Sed ac tempus arcu. Curabitur enim eros, accumsan sed mattis porttitor, interdum et est. Etiam eget nulla ante. Ut luctus justo sit amet risus suscipit porta.

Vivamus quis dignissim augue. In interdum tellus sed mattis volutpat. Maecenas ut neque egestas, maximus orci ut, scelerisque elit. Aliquam ornare, augue quis gravida vulputate, nibh urna imperdiet turpis, in porta justo dui id tellus. Donec elementum iaculis fringilla. Sed faucibus est diam, vitae facilisis ante feugiat non. Nam aliquet cursus ante, ac rutrum ligula faucibus eu. Integer sit amet faucibus justo, eget aliquet felis.

Etiam iaculis nisl justo, et vulputate nulla egestas sit amet. In mollis commodo turpis ac mollis. Suspendisse potenti. Nulla elit dui, luctus et varius vel, commodo in ligula. Suspendisse vehicula nec mauris eu molestie. Aliquam posuere tortor id nibh porta rhoncus. Vestibulum aliquam nec neque eget pulvinar. Proin quis consequat ex, eget scelerisque tortor. Curabitur maximus venenatis nunc nec commodo. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Nam congue, quam quis feugiat vestibulum, urna tortor condimentum metus, sed vestibulum velit quam a ipsum.

Sed eget finibus sem. Praesent congue neque et ipsum accumsan rhoncus. Vivamus volutpat semper sodales. Morbi quis nunc vehicula, rutrum nulla convallis, posuere tellus. Nulla vestibulum, arcu eu volutpat blandit, tortor libero finibus metus, vel dapibus orci urna et est. Duis sed suscipit nunc, eget luctus nisi. Fusce velit tortor, tincidunt sit amet pretium euismod, faucibus a elit.

Cras a leo magna. Duis at quam tortor. Donec faucibus vulputate tortor, ac sodales est. Pellentesque congue vitae eros in interdum. Suspendisse potenti. Pellentesque scelerisque, mauris vel pretium finibus, elit lorem varius quam, in fringilla augue orci id mi. Sed at laoreet diam. Duis semper velit non sapien viverra, quis rhoncus turpis egestas. Suspendisse elit eros, lobortis ut enim eu, congue convallis orci. Nam nisl odio, fringilla sed felis a, sollicitudin posuere arcu. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos.

Nam nunc lacus, porta in molestie at, tristique id justo. Proin nibh mauris, condimentum non metus ut, bibendum accumsan orci. Aliquam ullamcorper aliquet nisi vitae consectetur. Proin quis lectus quam. Vivamus placerat felis sem, et blandit nulla bibendum quis. Praesent suscipit neque est, quis interdum diam facilisis ut. Vestibulum et mattis ante. Vivamus arcu lorem, lobortis ut dolor sit amet, commodo tempus mauris. Nullam ornare quam ut cursus suscipit. Fusce et lectus ex. Sed blandit accumsan auctor. Curabitur quis commodo orci. Fusce in porta erat, ut fringilla nunc. Quisque a pharetra sem, vel lobortis diam. Donec cursus lacus lacinia nibh pulvinar finibus. Sed pellentesque odio et lacinia malesuada.

Donec laoreet erat dolor, non aliquam sapien maximus ut. Sed bibendum nunc vel tincidunt malesuada. Donec eu molestie lorem, at volutpat ligula. Nulla cursus ante at dolor congue iaculis. Praesent lobortis urna id lobortis ultricies. Etiam varius fermentum feugiat. Mauris at ligula velit. Morbi id accumsan ex, a cursus erat.

Mauris efficitur, arcu eget facilisis scelerisque, eros arcu egestas augue, eget luctus erat ante id nisi. Duis tincidunt feugiat felis dictum maximus. Sed nec purus massa. Ut ex mi, faucibus ut bibendum porttitor, maximus eu ligula. In a scelerisque elit, placerat pulvinar sapien. Aliquam sagittis mi non porttitor pellentesque. Phasellus id molestie nisl, ut euismod ex. Suspendisse gravida porta mi et fringilla. Nulla eget eros eleifend dui blandit aliquam interdum sed purus. Quisque condimentum malesuada justo, ut tincidunt felis fermentum nec.

Nunc auctor diam nec lacus tempus consequat. Cras rhoncus dictum purus, eu egestas purus volutpat in. Quisque mi nisl, hendrerit eu venenatis non, ornare quis leo. Donec semper elit eu commodo ultrices. Vestibulum non nisi nec nibh feugiat tincidunt nec et lacus. Praesent vitae nunc ut felis tempor volutpat id id enim. Lorem ipsum dolor sit amet, consectetur adipiscing elit.

Quisque ultrices vestibulum ligula at rhoncus. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Vestibulum sodales venenatis eros quis suscipit. Ut vehicula neque eu dictum pretium. Maecenas vestibulum rhoncus erat at eleifend. Vestibulum luctus sodales justo, quis lacinia turpis vulputate et. Quisque tristique neque at sem maximus elementum. Morbi nisi orci, tincidunt facilisis ultricies feugiat, iaculis a diam. Sed quis felis ullamcorper, porta velit non, blandit ipsum. Mauris luctus tellus vel mollis vestibulum. Donec efficitur pellentesque vehicula. Donec facilisis, tellus sit amet gravida porttitor, sem lorem fermentum justo, vitae vulputate mauris dui at libero. Sed orci est, laoreet id maximus ac, faucibus maximus arcu.

Sed consectetur volutpat tempus. Nunc tempus sapien ligula, ultrices suscipit dolor lacinia nec. Fusce mollis purus eu placerat venenatis. Mauris iaculis eget metus non rhoncus. Ut finibus pulvinar ante, non mattis ex sollicitudin vel. Nulla rutrum rhoncus ultrices. Integer pharetra, ipsum vitae blandit gravida, massa turpis faucibus dui, sed consectetur sapien augue et eros. Duis et nulla mi. Etiam luctus imperdiet nunc porta mollis. Suspendisse turpis nibh, aliquet quis nisl vel, iaculis malesuada mauris. Pellentesque iaculis egestas mi, dapibus posuere arcu venenatis at. Proin pretium semper leo. Nullam lacus urna, dignissim ut commodo quis, feugiat posuere leo. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Maecenas felis urna, posuere non blandit sit amet, pulvinar at massa. Nunc elit neque, commodo vel tristique sit amet, dictum vitae quam.

Donec nisi ligula, rhoncus sit amet viverra eu, aliquet nec felis. Morbi quis magna vel odio vestibulum commodo. Donec nec volutpat odio, eu egestas nulla. Aenean in neque nunc. Vestibulum tempor iaculis nisl, sit amet bibendum orci viverra ac. Curabitur magna enim, porta quis tellus sodales, pharetra vehicula ligula. Curabitur vulputate justo dui, et facilisis mi cursus sed. Phasellus orci arcu, aliquet vitae est a, consequat dictum nibh. Proin id mauris non quam condimentum sagittis. Aenean et tincidunt purus. Maecenas ut pharetra ante. Fusce sit amet metus pellentesque, ullamcorper risus et, pharetra purus. Integer id nisi a tortor pharetra accumsan.

Cras eu euismod tortor. Donec nec efficitur tellus, non volutpat erat. Morbi nec urna et neque tincidunt euismod ut id dolor. Suspendisse potenti. Sed at lobortis mauris, in posuere elit. Etiam sollicitudin metus vel ullamcorper volutpat. Donec efficitur tristique quam sed tristique. Donec lobortis lectus in egestas viverra. Nunc in turpis vitae odio lobortis ornare ac in nulla. Etiam feugiat purus a lacus rhoncus tincidunt. Vestibulum vitae scelerisque magna, vulputate tempus dolor. Phasellus sit amet ornare diam. Donec ac neque et lorem condimentum mattis. Aenean vel malesuada metus, non aliquam nibh. Curabitur facilisis tristique facilisis. Donec fringilla, justo vitae congue vulputate, ligula eros scelerisque erat, sit amet sollicitudin augue lorem vitae ipsum.

Vestibulum vulputate non turpis non lacinia. Vestibulum dapibus orci sed commodo rutrum. Praesent dignissim nulla euismod justo feugiat, et mollis diam mollis. Pellentesque non scelerisque felis. In sodales ante est, quis dapibus eros condimentum et. Donec eget ante urna. Vestibulum id ligula a nulla dignissim convallis. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Nullam rhoncus, turpis maximus elementum ultrices, quam ex porttitor ante, a venenatis quam eros a nulla. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Quisque eget velit ut libero gravida lobortis.

Quisque commodo porttitor eros porta tincidunt. Vestibulum pharetra orci eget elit placerat porttitor. Mauris hendrerit consectetur tortor. Morbi mattis ultricies elit, et aliquam velit mollis eu. Vivamus et semper magna, in laoreet augue. Quisque suscipit vel dui in porta. Ut ultrices, nibh quis finibus lobortis, ex ex porta odio, in vestibulum tellus erat sit amet augue. Maecenas cursus elit non semper consequat.

Suspendisse volutpat, diam vitae sollicitudin feugiat, lacus justo lacinia libero, vitae dictum mi sapien sed tortor. Fusce non nulla nec risus venenatis laoreet sed et eros. Pellentesque quis dictum est. Donec in nunc ac mi ultricies interdum. Suspendisse potenti. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Nam ac nulla vitae tellus blandit sagittis. Praesent eget nulla id lorem mollis congue vel at sapien. Suspendisse tincidunt tincidunt lectus eu aliquam. Fusce venenatis, libero sit amet tincidunt sagittis, velit erat blandit nisl, vel iaculis risus quam eget risus. Cras maximus ac nisl nec efficitur. Nam malesuada lacinia purus, quis commodo lacus. Aliquam aliquam orci sed urna hendrerit, in luctus lacus elementum. Nunc convallis at ex id tristique. Phasellus ut leo vestibulum, tempus urna eu, tincidunt ligula. Aenean ac arcu quis enim posuere malesuada nec eu nulla.

Aliquam ac magna odio. Morbi ut sapien ullamcorper, rutrum tortor et, blandit ante. Aliquam erat volutpat. Cras non pellentesque elit. Nulla mollis non dolor a semper. Aliquam porta vel eros luctus ultricies. Pellentesque ut ultricies mauris, vitae vehicula quam. Donec blandit arcu sed sem sodales pulvinar. Donec enim ligula, consequat sed mollis a, facilisis a turpis. Aliquam erat volutpat. Sed a dictum mi. Cras ultricies malesuada arcu sed hendrerit. Suspendisse ultricies ex ut lectus varius, convallis condimentum augue luctus. Pellentesque et turpis interdum, posuere nisl ut, tincidunt dolor.

Donec at ipsum orci. Aenean condimentum leo felis, ornare tristique augue eleifend sit amet. Praesent at mauris quam. Maecenas ac nunc a ipsum suscipit dapibus sit amet vitae felis. Curabitur consequat iaculis urna sit amet semper. Vivamus elit enim, pellentesque vitae diam quis, pretium aliquet justo. Donec non quam ut metus fermentum accumsan. Nulla enim lacus, consequat sit amet blandit vitae, ultrices vitae libero. Maecenas sed tempor nisi, quis euismod elit. Donec vitae laoreet sem, in rhoncus quam. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae; Nam tincidunt tempus est, at placerat magna volutpat in. Quisque vehicula sagittis rutrum.

Cras ultrices nisi sit amet enim porttitor, bibendum facilisis enim elementum. Proin vel dolor vel lorem elementum elementum. Ut varius lobortis vehicula. In laoreet felis mi, ullamcorper gravida elit efficitur eu. Praesent vitae dolor interdum, vestibulum metus in, sodales ex. Nulla leo libero, elementum at congue quis, fringilla sit amet lacus. Sed viverra, mi eget sodales sollicitudin, urna nisl accumsan tortor, nec ultrices nunc lectus eget justo. Mauris vel massa augue. Maecenas nec leo neque. Suspendisse feugiat accumsan semper.

Aenean pellentesque dolor et rhoncus pharetra. Maecenas ac turpis condimentum arcu malesuada vehicula. Nullam feugiat imperdiet tristique. Sed erat tortor, mattis non tempus ac, mattis sit amet nulla. Nam scelerisque, urna eu tempor laoreet, ante nulla consectetur felis, a mattis nisl leo et risus. Maecenas leo sapien, facilisis sit amet augue vitae, aliquet semper ipsum. Nunc est nunc, rhoncus at lacus cursus, ullamcorper blandit nisi.

Quisque mattis ante euismod massa fringilla, at venenatis dui rhoncus. Maecenas et fermentum nisi. Aliquam facilisis, dui a interdum congue, tortor diam ullamcorper leo, lobortis molestie quam urna in arcu. Nulla sapien massa, consectetur vel blandit at, congue eget urna. Mauris ornare vestibulum diam a auctor. Sed egestas purus sapien. Quisque feugiat et neque eget sodales. Praesent varius, dui a sollicitudin congue, elit eros congue diam, sit amet condimentum purus sem nec arcu. Etiam quis ex in arcu gravida hendrerit. Aenean luctus, enim eu faucibus luctus, magna ante interdum neque, ut tincidunt odio lacus ac urna. Suspendisse potenti. Vivamus at rhoncus justo, sit amet semper lacus. Vestibulum a porta neque, at porta lectus. Vivamus sed condimentum sem. Sed aliquet dolor at odio tristique, sit amet dapibus nisl eleifend.

Morbi malesuada lectus velit, id efficitur ipsum laoreet et. Vivamus egestas ligula non orci hendrerit venenatis. Ut ultricies, nunc quis facilisis efficitur, urna augue sodales urna, eu ultricies quam quam sed augue. Quisque a sem tellus. Morbi dignissim, massa vel venenatis porta, nulla augue elementum leo, vel scelerisque neque ex in eros. Quisque feugiat felis in enim pharetra, non ultrices elit laoreet. Ut eu urna quis ipsum tempor suscipit vitae ut turpis. Sed pellentesque enim sed ante eleifend, a tincidunt mi vestibulum. Cras fringilla imperdiet lorem ac dictum. Vivamus pellentesque id mi vel faucibus.

Mauris nec lorem sed nisi imperdiet bibendum molestie vel quam. Mauris vehicula urna magna, a tempus lorem tincidunt non. Pellentesque sit amet bibendum urna. Duis sit amet arcu sed diam gravida efficitur. Nullam vitae neque mauris. Integer nec enim vitae diam imperdiet scelerisque in id velit. Phasellus pellentesque, dolor sed fermentum condimentum, lorem nunc laoreet eros, sed tincidunt augue neque sed dolor.

Sed pharetra augue eu ante dapibus, et finibus mi blandit. Nullam feugiat suscipit magna, in aliquet nibh condimentum ut. Duis commodo aliquam lectus, eu tincidunt eros accumsan sit amet. Duis mattis orci sit amet nisl fermentum suscipit. In sed odio vel tellus facilisis volutpat. Etiam at dolor id turpis auctor mollis. Quisque dignissim suscipit nulla, vitae sollicitudin urna sollicitudin quis.

Integer sed tincidunt orci, ut auctor purus. Nunc eget convallis sapien. Curabitur libero felis, facilisis et nibh non, tincidunt placerat nisl. Donec sodales tellus nec feugiat egestas. Pellentesque aliquam diam vehicula, tincidunt orci eget, volutpat odio. Cras eget commodo ipsum, vitae mattis turpis. Morbi lorem risus, venenatis a dolor mattis, bibendum varius dui. Sed sed orci eget tellus placerat ultricies id sed ipsum. Aliquam id felis quis ante elementum porta. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae; Donec maximus iaculis urna, eget auctor enim ornare vitae. Proin ipsum ligula, sagittis et dui vitae, feugiat accumsan eros. Nullam eu mauris vitae erat gravida consequat. Fusce sollicitudin erat in risus convallis egestas. Praesent hendrerit lacinia semper. In rutrum consequat massa, vel lacinia felis fermentum vitae.

Vivamus laoreet dolor vel sollicitudin porta. Donec aliquam lectus massa, sed vestibulum ligula aliquam sed. Vivamus in nulla quis ipsum scelerisque faucibus pharetra sed leo. Aliquam vitae tortor at erat bibendum tempus non non enim. Nunc sit amet interdum dui. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Morbi auctor ligula eget convallis tempus. Vivamus ac massa quis diam mattis mollis. Aenean a venenatis arcu, et viverra mauris. Aenean eget leo erat. Vivamus blandit auctor ex interdum elementum. Aliquam vehicula ultricies consequat.

Praesent blandit mi non velit dapibus dictum. Aenean ligula arcu, porta a nunc in, suscipit tristique mauris. Cras pretium mauris sit amet ipsum ultricies iaculis. Vivamus ut fringilla turpis, ut pulvinar magna. Mauris facilisis dictum arcu, vel feugiat odio cursus mattis. Nulla at elit eget orci convallis sollicitudin. Nullam in scelerisque nunc. Interdum et malesuada fames ac ante ipsum primis in faucibus. Fusce a mollis lacus, pretium iaculis leo. Donec sollicitudin purus a nunc consequat, nec sagittis risus consectetur. Quisque auctor quis arcu sit amet semper. Proin et turpis odio. In sed pretium enim, ut semper tortor. Vestibulum eget ornare velit, id aliquet erat.'''
    
    rslt = None
    for frag in make_frags(s):
        rslt = receive_frag(frag)
        
    assert rslt == s, "got {}".format(rslt)