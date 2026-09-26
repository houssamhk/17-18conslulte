from typing import List, Optional
from .regex_detector import DetectedEntity
import logging

class NLPDetector:
    """
    Contextual NLP Detection Layer — ONNX-optimized Transformer NER.
    Uses CAMeL-Lab/bert-base-arabic-camelbert-msa-ner for Arabic NER.
    """
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or "CAMeL-Lab/bert-base-arabic-camelbert-msa-ner"
        self._pipeline = None
        self._is_available = False
        
    def load_model(self, model_path: Optional[str] = None) -> bool:
        """Lazy loads the NER model. Tries ONNX runtime first, falls back to standard transformers."""
        if self._pipeline is not None:
            return True
            
        if model_path:
            self.model_path = model_path

        try:
            from transformers import pipeline, AutoTokenizer
            try:
                from optimum.onnxruntime import ORTModelForTokenClassification
                
                # Attempt ONNX load
                tokenizer = AutoTokenizer.from_pretrained(self.model_path)
                # Ensure export=True if loading from Hub and not already ONNX, but in production this should point to a local ONNX model
                try:
                    model = ORTModelForTokenClassification.from_pretrained(self.model_path)
                except Exception:
                    # Fallback if export is needed (development only)
                    model = ORTModelForTokenClassification.from_pretrained(self.model_path, export=True)
                    
                self._pipeline = pipeline(
                    "token-classification",
                    model=model,
                    tokenizer=tokenizer,
                    aggregation_strategy="simple"
                )
                logging.info(f"Loaded ONNX NER model from {self.model_path}")
                self._is_available = True
                return True
                
            except ImportError:
                logging.warning("optimum[onnxruntime] not installed. Falling back to standard transformers.")
                
            # Fallback to standard transformers
            self._pipeline = pipeline(
                "token-classification",
                model=self.model_path,
                aggregation_strategy="simple"
            )
            logging.info(f"Loaded standard PyTorch NER model from {self.model_path}")
            self._is_available = True
            return True
            
        except ImportError:
            logging.error("transformers library is not installed. NLP detection unavailable.")
            self._is_available = False
            return False
        except Exception as e:
            logging.error(f"Failed to load NLP model: {e}")
            self._is_available = False
            return False

    def is_available(self) -> bool:
        return self._is_available

    def detect(self, text: str) -> List[DetectedEntity]:
        """Detect entities using the loaded NLP model."""
        if not self._is_available or not self._pipeline or not text.strip():
            return []
            
        try:
            results = self._pipeline(text)
            entities = []
            
            for res in results:
                # Map entity groups from model to our standard labels
                raw_group = res.get('entity_group', res.get('entity', 'MISC'))
                
                # Remove B- and I- prefixes if present
                if raw_group.startswith('B-') or raw_group.startswith('I-'):
                    group = raw_group[2:]
                else:
                    group = raw_group
                    
                entities.append(DetectedEntity(
                    text=res['word'],
                    entity_type=group,
                    start=res['start'],
                    end=res['end'],
                    confidence=res['score'],
                    source="nlp"
                ))
            return entities
            
        except Exception as e:
            logging.error(f"NLP detection error: {e}")
            return []
