import pydeep
from os.path import abspath, isfile, isdir, join
import hashlib
import base64
from struct import unpack
from glob import iglob


def get_all_7_char_chunks(h):
    return set((unpack("<Q", base64.b64decode(h[i:i + 7] + "=") + "\x00\x00\x00")[0] for i in xrange(len(h) - 6)))


def preprocess_hash(h):
    block_size, h = h.split(":", 1)
    block_size = int(block_size)

    # Reduce any sequence of the same char greater than 3 to 3
    for c in set(list(h)):
        while c * 4 in h:
            h = h.replace(c * 4, c * 3)

    block_data, double_block_data = h.split(":")

    return block_size, get_all_7_char_chunks(block_data), get_all_7_char_chunks(double_block_data)


def enumerate_paths(path_list, recursive_scan):
    ret_paths = []
    while len(path_list) != 0:
        file_path = abspath(path_list[0])
        del path_list[0]
        if isfile(file_path):
            ret_paths.append(file_path)
        elif isdir(file_path):
            for p in iglob(join(file_path, "*")):
                p = join(file_path, p)
                if isfile(p) or (isdir(p) and recursive_scan):
                    path_list.append(p)
    return ret_paths


def generate_gexf(bin_scores):
    ids = {}
    gexf = '<?xml version="1.0" encoding="UTF-8"?>' \
           '<gexf xmlns="http://www.gexf.net/1.2draft" version="1.2">' \
           '<meta lastmodifieddate="2009-03-20">' \
           '<creator>bwall</creator>' \
           '<description></description>' \
           '</meta>' \
           '<graph mode="static" defaultedgetype="directed">' \
           '<attributes class="node" mode="static">' \
           '<attribute id="modularity_class" title="Modularity Class" type="integer"></attribute>' \
           '</attributes>' \
           '<nodes>'

    key_index = 0
    for path_keys in bin_scores.keys():
        gexf += '<node id="{0}" label="{1}">' \
                '<attvalues><attvalue for="modularity_class" value="1"></attvalue></attvalues>' \
                '</node>'.format(key_index, path_keys)
        ids[path_keys] = key_index
        key_index += 1

    gexf += '</nodes>' \
            '<edges>'

    edge_index = 0
    for path_key in bin_scores.keys():
        for other_key in bin_scores[path_key].keys():
            gexf += '<edge id="{0}" source="{1}" target="{2}" weight="{3}" />'.format(edge_index, ids[path_key],
                                                                                      ids[other_key],
                                                                                      float(bin_scores[path_key]
                                                                                            [other_key]) / 100)
            edge_index += 1

    gexf += '</edges>' \
            '</graph>' \
            '</gexf>'

    return gexf


def get_version():
    return "1.2.0"


def ssdeep_cluster(root_paths,
                   recursive=False,
                   dontcompute=False,
                   calculate_sha256=False,
                   should_print=False,
                   score_threshold=0):
    paths = enumerate_paths(root_paths, recursive)
    hashes = {}
    sha256s = {}
    integerdb = {}

    matches = {}
    scores = {}

    def add_to_integer_db(block_size, chunk, path):
        if block_size not in integerdb:
            integerdb[block_size] = {}

        similar_to = set()
        for i in chunk:
            if i not in integerdb[block_size]:
                integerdb[block_size][i] = set()
            else:
                similar_to |= integerdb[block_size][i]
            integerdb[block_size][i].add(path)

        return similar_to

    if dontcompute:
        real_paths = set()
        for path in paths:
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if len(line) == 0:
                        continue
                    real_paths.add(line)
        paths = list(real_paths)

    for path in paths:
        if not dontcompute:
            hashes[path] = pydeep.hash_file(path)
            if calculate_sha256:
                sha256s[path] = hashlib.sha256(file(path, 'rb').read()).hexdigest()
        else:
            if "," in path:
                shash, path = path.split(",", 1)
                path = path.strip('"')
            else:
                shash = path
            hashes[path] = shash
            if calculate_sha256:
                sha256s[path] = \
                    hashlib.sha256(file(path, 'rb').read()).hexdigest() if isfile(path)\
                        else hashlib.sha256(path).hexdigest()
        block_size, chunk, double_chunk = preprocess_hash(hashes[path])

        similar_to = add_to_integer_db(block_size, chunk, path) | add_to_integer_db(block_size * 2, double_chunk, path)

        h = hashes[path]
        matches[path] = set()
        for other in similar_to:
            score = pydeep.compare(h, hashes[other])
            if score > score_threshold:
                matches[path].add(other)
                matches[other].add(path)
                if path not in scores:
                    scores[path] = {}
                if other not in scores[path]:
                    scores[path][other] = score

                if other not in scores:
                    scores[other] = {}
                if path not in scores[other]:
                    scores[other][path] = score

        if should_print:
            print "{0}\tSHA256: {1}\tssdeep: {2}".format(path, sha256s.get(path), hashes[path])

    groups = []
    for path in matches.keys():
        in_a_group = False
        for g in xrange(len(groups)):
            if path in groups[g]:
                in_a_group = True
                continue
            should_add = True
            for h in groups[g]:
                if h not in matches[path]:
                    should_add = False
            if should_add:
                groups[g].append(path)
                in_a_group = True
        if not in_a_group:
            groups.append([path])

    for g in xrange(len(groups)):
        groups[g].sort()

    return groups, hashes, scores, sha256s
