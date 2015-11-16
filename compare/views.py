# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys
import pymongo

from django.conf import settings
from django.template import RequestContext
from django.shortcuts import render_to_response
from django.views.decorators.http import require_safe

from web import until

sys.path.append(settings.CUCKOO_PATH)

import lib.cuckoo.common.compare as compare

import pprint
pp = pprint.PrettyPrinter()

results_db = pymongo.MongoClient(settings.MONGO_HOST, settings.MONGO_PORT)[settings.MONGO_DB]

@require_safe
def left(request, left_id):

    decrpt_task_id = until.decrpt(left_id)
    left = results_db.analysis.find_one({"info.id": int(decrpt_task_id)}, {"target": 1, "info": 1})
    if not left:
        return render_to_response("error.html",
                                  {"error": "No analysis found with specified ID"},
                                  context_instance=RequestContext(request))
    else:
        if "info" in left:
           left["info"]["base64id"] = left_id

    if left["target"]["category"] == "url":
       records = results_db.analysis.find(
            {
                "$and": [
                    {"target.url": left["target"]["url"]},
                    {"info.id": {"$ne": int(decrpt_task_id)}}
                ]
            },
            {"target": 1, "info": 1}
        )
    else:   	
      #print decrpt_task_id
      #print left["target"]["file"]["md5"]
      #Select all analyses with same file hash.
      records = results_db.analysis.find(
          {
              "$and": [
                  {"target.file.md5": left["target"]["file"]["md5"]},
                  {"info.id": {"$ne": int(decrpt_task_id)}}
              ]
          },
          {"target": 1, "info": 1}
      )
      
    compare_element = []

    for single_record in records:
      new = single_record

      new["info"]["base64id"] = until.encrpt(new["info"]["id"])
      compare_element.append(new)


    return render_to_response("compare/left.html",
                              {"left": left, "records": compare_element},
                              context_instance=RequestContext(request))

@require_safe
def hash(request, left_id, right_hash):
    left = results_db.analysis.find_one({"info.id": int(left_id)}, {"target": 1, "info": 1})
    if not left:
        return render_to_response("error.html",
                                  {"error": "No analysis found with specified ID"},
                                  context_instance=RequestContext(request))

    # Select all analyses with same file hash.
    records = results_db.analysis.find(
        {
            "$and": [
                {"target.file.md5": right_hash},
                {"info.id": {"$ne": int(left_id)}}
            ]
        },
        {"target": 1, "info": 1}
    )

    # Select all analyses with specified file hash.
    return render_to_response("compare/hash.html",
                              {"left": left, "records": records, "hash": right_hash},
                              context_instance=RequestContext(request))

@require_safe
def both(request, left_id, right_id):
    decrpt_left = until.decrpt(left_id)
    decrpt_right = until.decrpt(right_id)
    left = results_db.analysis.find_one({"info.id": int(decrpt_left)}, {"target": 1, "info": 1})
    if "info" in left:
      left["info"]["base64id"] = left_id
    right = results_db.analysis.find_one({"info.id": int(decrpt_right)}, {"target": 1, "info": 1})
    if "info" in right:
      right["info"]["base64id"] = right_id

    print decrpt_left
    print decrpt_right
    # Execute comparison.
    counts = compare.helper_percentages_mongo(results_db, decrpt_left, decrpt_right)
    
    pp.pprint(counts[decrpt_left])
    pp.pprint(counts[decrpt_right])

    return render_to_response("compare/both.html",
                              {"left": left, "right": right, "left_counts": counts[decrpt_left],
                               "right_counts": counts[decrpt_right]},
                               context_instance=RequestContext(request))
