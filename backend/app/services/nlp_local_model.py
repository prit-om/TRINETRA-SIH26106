"""Optional local transformer scorer. Falls back cleanly when model weights are absent."""
from __future__ import annotations
import os
_model=None; _tokenizer=None

def available(): return bool(os.getenv('TRINETRA_NLP_MODEL'))

def score(text: str) -> dict|None:
    global _model,_tokenizer
    model_name=os.getenv('TRINETRA_NLP_MODEL')
    if not model_name: return None
    try:
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        import torch
        if _model is None:
            _tokenizer=AutoTokenizer.from_pretrained(model_name,local_files_only=os.getenv('TRINETRA_NLP_LOCAL_ONLY','true').lower()=='true')
            _model=AutoModelForSequenceClassification.from_pretrained(model_name,local_files_only=os.getenv('TRINETRA_NLP_LOCAL_ONLY','true').lower()=='true')
        batch=_tokenizer(text[:12000],return_tensors='pt',truncation=True,max_length=512)
        with torch.no_grad(): probs=torch.softmax(_model(**batch).logits,dim=-1)[0].tolist()
        malicious=float(max(probs)) if probs else 0.0
        return {'model_used':'local-transformer','model_name':model_name,'malicious_probability':malicious}
    except Exception: return None
